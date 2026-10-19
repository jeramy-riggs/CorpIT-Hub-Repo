#!/usr/bin/env python3
"""
apmoves.py — Wi-Fi client movement between Meraki APs.

Meraki only reports where a client is RIGHT NOW, so roaming has to be
derived. Each run snapshots the live client list per network into
net_ap_clients; any client whose recentDeviceName differs from the
previous snapshot becomes a real row in net_ap_moves. Per-AP client
counts are sampled every run into net_ap_counts so the Network
Observatory can draw a trend. Writes the same SQLite cache the rest of
/api/netswitch reads — nothing here talks to the switches.
"""
from corpit_sqlite import connect_durable
import sys, os, sqlite3, json, time, urllib.request, urllib.error

DB      = os.environ.get("NET_DB", "/var/www/corpit-hub-api/data/netfleet.db")
ENVFILE = os.environ.get("API_ENV", "/var/www/corpit-hub-api/.env")
NETS    = os.environ.get("NET_MERAKI_NETS",
                         "SNA01=N_582090251837658123,DFW02=N_832040031156699632")
TIMESPAN  = int(os.environ.get("NET_AP_TIMESPAN", "900"))
KEEP_DAYS = int(os.environ.get("NET_AP_KEEP_DAYS", "14"))
MERAKI_B  = "https://api.meraki.com/api/v1"

def api_key():
    k = os.environ.get("MERAKI_API_KEY")
    if k: return k.strip()
    try:
        with open(ENVFILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("MERAKI_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception as e:
        print("# env %s: %s" % (ENVFILE, e), file=sys.stderr)
    return None

def mk_get(path, key, timeout=30):
    req = urllib.request.Request(MERAKI_B + path, headers={
        "X-Cisco-Meraki-API-Key": key, "Accept": "application/json"})
    for attempt in (0, 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt == 0:      # Meraki rate limit: honour Retry-After once
                time.sleep(float(e.headers.get("Retry-After") or 2)); continue
            raise
    raise RuntimeError("Meraki 429 retry exhausted " + path)

def networks():
    out = []
    for part in NETS.split(","):
        name, _, nid = part.strip().partition("=")
        if name and nid: out.append((name.strip(), nid.strip()))
    return out

def ensure(db):
    db.executescript("""
    PRAGMA journal_mode=WAL;
    -- last known AP per client: the snapshot the next run diffs against
    CREATE TABLE IF NOT EXISTS net_ap_clients(
      mac TEXT PRIMARY KEY, network TEXT, ap TEXT, ssid TEXT, ip TEXT,
      label TEXT, ts INTEGER);
    CREATE INDEX IF NOT EXISTS ix_apc_ap ON net_ap_clients(ap);

    -- one row per observed AP change (a real roam, never inferred)
    CREATE TABLE IF NOT EXISTS net_ap_moves(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mac TEXT, label TEXT, network TEXT, from_ap TEXT, to_ap TEXT,
      ssid TEXT, ts INTEGER);
    CREATE INDEX IF NOT EXISTS ix_apmoves_ts ON net_ap_moves(ts);
    CREATE INDEX IF NOT EXISTS ix_apmoves_mac ON net_ap_moves(mac, ts);

    -- per-AP client count, one sample per run
    CREATE TABLE IF NOT EXISTS net_ap_counts(
      network TEXT, ap TEXT, ts INTEGER, clients INTEGER,
      PRIMARY KEY(network, ap, ts));
    CREATE INDEX IF NOT EXISTS ix_apcounts_ts ON net_ap_counts(ts);
    """)
    # self-healing migrations for DBs created before a column existed
    for tbl, col, typ in (("net_ap_clients", "label", "TEXT"),
                          ("net_ap_moves", "ssid", "TEXT"),
                          ("net_ap_counts", "clients", "INTEGER")):
        try: db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (tbl, col, typ))
        except Exception: pass

def main():
    t0 = time.time()
    key = api_key()
    if not key:
        print(json.dumps({"ok": False, "error": "NO_API_KEY", "env": ENVFILE}))
        return 1
    seen, counts, errors = [], {}, {}
    nets = networks()
    for name, nid in nets:
        try:
            cls = mk_get("/networks/%s/clients?timespan=%d&perPage=1000" % (nid, TIMESPAN), key)
        except Exception as e:
            errors[name] = str(e)
            print("# clients %s: %s" % (name, e), file=sys.stderr); continue
        for c in cls:
            mac = (c.get("mac") or "").lower()
            ap  = c.get("recentDeviceName") or ""
            if not mac or not ap: continue      # no AP attribution = nothing to diff
            seen.append((mac, name, ap, c.get("ssid"), c.get("ip"), c.get("description")))
            counts[(name, ap)] = counts.get((name, ap), 0) + 1

    db = connect_durable(DB, timeout=30); ensure(db)
    now = int(time.time())
    prev = {m: a for m, a in db.execute("SELECT mac, ap FROM net_ap_clients")}
    moves = 0
    for mac, net, ap, ssid, ip, label in seen:
        was = prev.get(mac)
        if was and was != ap:
            db.execute("""INSERT INTO net_ap_moves(mac,label,network,from_ap,to_ap,ssid,ts)
                          VALUES(?,?,?,?,?,?,?)""", (mac, label, net, was, ap, ssid, now))
            moves += 1
        db.execute("""INSERT INTO net_ap_clients(mac,network,ap,ssid,ip,label,ts)
                      VALUES(?,?,?,?,?,?,?)
                      ON CONFLICT(mac) DO UPDATE SET network=excluded.network,ap=excluded.ap,
                        ssid=excluded.ssid,ip=excluded.ip,label=excluded.label,ts=excluded.ts""",
                   (mac, net, ap, ssid, ip, label, now))
    for (net, ap), n in counts.items():
        db.execute("""INSERT INTO net_ap_counts(network,ap,ts,clients) VALUES(?,?,?,?)
                      ON CONFLICT(network,ap,ts) DO UPDATE SET clients=excluded.clients""",
                   (net, ap, now, n))
    cut = now - KEEP_DAYS * 86400
    db.execute("DELETE FROM net_ap_moves   WHERE ts < ?", (cut,))
    db.execute("DELETE FROM net_ap_counts  WHERE ts < ?", (cut,))
    db.execute("DELETE FROM net_ap_clients WHERE ts < ?", (cut,))
    db.commit(); db.close()

    out = {"ok": True, "networks": len(nets) - len(errors), "clients": len(seen),
           "moves": moves, "run_ms": int((time.time() - t0) * 1000)}
    if errors: out["errors"] = errors
    print(json.dumps(out))
    return 0

if __name__ == "__main__":
    sys.exit(main())
