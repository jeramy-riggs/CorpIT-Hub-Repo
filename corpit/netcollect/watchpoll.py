#!/usr/bin/env python3
"""
watchpoll.py — high-frequency sampling of pinned items.

The hourly sweep is deliberately coarse. When you are chasing an intermittent
fault you need dense history on a few specific things, so anything pinned to
the watch list gets sampled every few minutes and kept for a long time.

Per run, for each active watch:
  • port   -> counters + link state from the switch, straight over SNMP
  • device -> ICMP reachability + where it is currently learned
  • ap     -> nothing here (Meraki is polled by the API layer)
Samples land in net_watch_samples; a change worth noticing becomes a row in
net_watch_events, so the timeline shows what happened rather than just numbers.
"""
from corpit_sqlite import connect_durable
import sys, os, sqlite3, time, json, subprocess, re
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snmp2 import get, dec
from diagnose import diagnose_port, diagnose_reach, worst

COMM = os.environ.get("NET_SNMP_COMM")
if not COMM:
    sys.exit("NET_SNMP_COMM is unset. The SNMP RO community is supplied by "
             "/etc/corpit/netcollect.env (systemd EnvironmentFile); it is deliberately "
             "not defaulted in source.")
DB   = os.environ.get("NET_DB", "/var/www/corpit-hub-api/data/netfleet.db")
KEEP_DAYS = int(os.environ.get("NET_WATCH_KEEP_DAYS", "120"))

IFOPER="1.3.6.1.2.1.2.2.1.8"; IFADMIN="1.3.6.1.2.1.2.2.1.7"
IFSPEED="1.3.6.1.2.1.31.1.1.1.15"; IFINERR="1.3.6.1.2.1.2.2.1.14"
IFOUTERR="1.3.6.1.2.1.2.2.1.20"; IFOUTDISC="1.3.6.1.2.1.2.2.1.19"
DOT3FCS="1.3.6.1.2.1.10.7.2.1.3"; DOT3DUP="1.3.6.1.2.1.10.7.2.1.19"
IFHCIN="1.3.6.1.2.1.31.1.1.1.6"; IFHCOUT="1.3.6.1.2.1.31.1.1.1.10"

def ensure(db):
    db.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS net_watch(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT,            -- port | device | ap
      ref TEXT,             -- port: "<switch_ip>:<ifindex>"  device: ip|mac  ap: serial
      label TEXT, meta TEXT,
      created_by TEXT, created_at INTEGER, active INTEGER DEFAULT 1,
      UNIQUE(kind, ref));
    CREATE TABLE IF NOT EXISTS net_watch_samples(
      watch_id INTEGER, ts INTEGER, data TEXT,
      PRIMARY KEY(watch_id, ts));
    CREATE INDEX IF NOT EXISTS ix_ws_ts ON net_watch_samples(watch_id, ts);
    CREATE TABLE IF NOT EXISTS net_watch_events(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      watch_id INTEGER, ts INTEGER, severity TEXT, kind TEXT, message TEXT);
    CREATE INDEX IF NOT EXISTS ix_we ON net_watch_events(watch_id, ts);
    """)

def g1(ip, oid):
    try:
        v = get(ip, COMM, oid, timeout=3)[0]; return dec(v[1], v[2])
    except Exception: return None

def ping(ip):
    try:
        out = subprocess.run(["ping","-c","2","-W","1",ip], capture_output=True, text=True, timeout=6).stdout
        m = re.search(r'(\d+)% packet loss', out); loss = int(m.group(1)) if m else 100
        r = re.search(r'=\s*[\d.]+/([\d.]+)/', out)
        return {"alive": loss < 100, "loss_pct": loss, "rtt_ms": round(float(r.group(1)),1) if r else None}
    except Exception:
        return {"alive": False, "loss_pct": 100, "rtt_ms": None}

def sample_port(ref):
    sw, ifx = ref.split(":", 1)
    d = {"oper": {1:"up",2:"down",3:"testing",7:"lowerLayerDown"}.get(g1(sw, IFOPER+"."+ifx)),
         "admin": {1:"up",2:"down"}.get(g1(sw, IFADMIN+"."+ifx)),
         "speed": g1(sw, IFSPEED+"."+ifx),
         "duplex": {1:"unknown",2:"half",3:"full"}.get(g1(sw, DOT3DUP+"."+ifx)),
         "in_err": g1(sw, IFINERR+"."+ifx), "out_err": g1(sw, IFOUTERR+"."+ifx),
         "crc": g1(sw, DOT3FCS+"."+ifx), "out_disc": g1(sw, IFOUTDISC+"."+ifx),
         "in_oct": g1(sw, IFHCIN+"."+ifx), "out_oct": g1(sw, IFHCOUT+"."+ifx)}
    return d

def sample_device(ref, db):
    d = {}
    ip = ref if re.match(r'^\d+\.\d+\.\d+\.\d+$', ref) else None
    mac = None if ip else ref.lower()
    if not ip and mac:
        row = db.execute("SELECT ip FROM net_arp WHERE mac=?", (mac,)).fetchone()
        ip = row[0] if row else None
    if ip: d["reach"] = ping(ip); d["ip"] = ip
    if mac or ip:
        m = mac
        if not m and ip:
            row = db.execute("SELECT mac FROM net_arp WHERE ip=?", (ip,)).fetchone()
            m = row[0] if row else None
        if m:
            row = db.execute(
                "SELECT switch, port, vlan FROM net_cam WHERE mac=? ORDER BY rowid LIMIT 1", (m,)).fetchone()
            if row: d["at"] = {"switch": row[0], "port": row[1], "vlan": row[2]}
            d["mac"] = m
    return d

def diff_events(prev, cur, kind):
    """Only say something when something actually changed."""
    ev = []
    if not prev: return ev
    if kind == "port":
        if prev.get("oper") != cur.get("oper"):
            sev = "critical" if cur.get("oper") != "up" else "info"
            ev.append((sev, "link", "Link went %s (was %s)" % (cur.get("oper"), prev.get("oper"))))
        for k, lbl in (("crc","CRC"), ("in_err","input errors"), ("out_err","output errors")):
            a, b = prev.get(k) or 0, cur.get(k) or 0
            if isinstance(a,int) and isinstance(b,int) and b > a:
                ev.append(("warn", k, "+%s %s" % (format(b-a, ","), lbl)))
        if prev.get("speed") != cur.get("speed") and cur.get("speed"):
            ev.append(("warn", "speed", "Renegotiated to %s Mbps (was %s)" % (cur.get("speed"), prev.get("speed"))))
        if prev.get("duplex") != cur.get("duplex") and cur.get("duplex"):
            ev.append(("warn", "duplex", "Duplex changed to %s" % cur.get("duplex")))
    elif kind == "device":
        pa = (prev.get("reach") or {}).get("alive"); ca = (cur.get("reach") or {}).get("alive")
        if pa is not None and pa != ca:
            ev.append(("critical" if not ca else "info", "reach",
                       "Stopped responding" if not ca else "Back online"))
        pat, cat = prev.get("at") or {}, cur.get("at") or {}
        if pat.get("port") and cat.get("port") and pat.get("port") != cat.get("port"):
            ev.append(("info", "moved", "Moved from %s %s to %s %s" %
                       (pat.get("switch"), pat.get("port"), cat.get("switch"), cat.get("port"))))
    return ev

def main():
    db = connect_durable(DB, timeout=30); ensure(db)
    rows = db.execute("SELECT id,kind,ref FROM net_watch WHERE active=1").fetchall()
    if not rows:
        print(json.dumps({"ok": True, "watched": 0})); return
    now = int(time.time())

    def work(r):
        wid, kind, ref = r
        try:
            if kind == "port":   return wid, kind, sample_port(ref)
            if kind == "device": return wid, kind, sample_device(ref, sqlite3.connect(DB, timeout=20))
        except Exception as e:
            return wid, kind, {"error": str(e)}
        return wid, kind, {}

    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for f in as_completed([ex.submit(work, r) for r in rows]):
            results.append(f.result())

    n_ev = 0
    for wid, kind, data in results:
        prow = db.execute(
            "SELECT data FROM net_watch_samples WHERE watch_id=? ORDER BY ts DESC LIMIT 1", (wid,)).fetchone()
        prev = json.loads(prow[0]) if prow else None
        # attach a probable cause to the sample itself
        if kind == "port":
            data["diag"] = diagnose_port(dict(port="", descr="", **{k: data.get(k) for k in
                ("oper","admin","speed","in_err","out_err","crc","out_disc","duplex")}, mac_count=0))
        elif kind == "device":
            data["diag"] = diagnose_reach(data.get("reach"))
        db.execute("INSERT OR REPLACE INTO net_watch_samples(watch_id,ts,data) VALUES(?,?,?)",
                   (wid, now, json.dumps(data)))
        for sev, k, msg in diff_events(prev, data, kind):
            db.execute("INSERT INTO net_watch_events(watch_id,ts,severity,kind,message) VALUES(?,?,?,?,?)",
                       (wid, now, sev, k, msg)); n_ev += 1

    cutoff = now - KEEP_DAYS*86400
    db.execute("DELETE FROM net_watch_samples WHERE ts < ?", (cutoff,))
    db.execute("DELETE FROM net_watch_events  WHERE ts < ?", (cutoff,))
    db.commit(); db.close()
    print(json.dumps({"ok": True, "watched": len(rows), "events": n_ev, "keep_days": KEEP_DAYS}))

if __name__ == "__main__":
    main()
