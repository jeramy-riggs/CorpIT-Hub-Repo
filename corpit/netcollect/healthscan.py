#!/usr/bin/env python3
"""
Network health scan — hourly sweep across every switch.

Collects, per run:
  • every port's state + counters      -> net_ports        (current)
  • flagged problems only              -> net_port_issues  (current, for the feed)
  • hourly counter snapshot            -> net_port_stats   (HISTORY, 30 days)
  • CAM: which MAC is on which port    -> net_cam          (current)
  • MAC presence over time             -> net_cam_seen     (HISTORY, first/last seen)

History retention is what makes "what did this look like 72 hours ago" answerable.
Never call this inline from a request — a full sweep is minutes.
"""
from corpit_sqlite import connect_durable
import sys, os, sqlite3, time, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snmp2 import walk, dec
from diagnose import diagnose_port
import json as _json

COMM = os.environ.get("NET_SNMP_COMM")
if not COMM:
    sys.exit("NET_SNMP_COMM is unset. The SNMP RO community is supplied by "
             "/etc/corpit/netcollect.env (systemd EnvironmentFile); it is deliberately "
             "not defaulted in source.")
DB   = os.environ.get("NET_DB", "/var/www/corpit-hub-api/data/netfleet.db")
KEEP_STATS_DAYS = int(os.environ.get("NET_KEEP_STATS_DAYS", "30"))
KEEP_SEEN_DAYS  = int(os.environ.get("NET_KEEP_SEEN_DAYS", "30"))

COLS = {"oper":"1.3.6.1.2.1.2.2.1.8","admin":"1.3.6.1.2.1.2.2.1.7",
        "inerr":"1.3.6.1.2.1.2.2.1.14","outerr":"1.3.6.1.2.1.2.2.1.20",
        "crc":"1.3.6.1.2.1.10.7.2.1.3","outdisc":"1.3.6.1.2.1.2.2.1.19",
        "name":"1.3.6.1.2.1.31.1.1.1.1","alias":"1.3.6.1.2.1.31.1.1.1.18",
        "speed":"1.3.6.1.2.1.31.1.1.1.15",
        # dot3StatsDuplexStatus (1=unknown 2=half 3=full). Same dot3 table the
        # CRC counter already comes from, so it costs one more walk and adds no
        # new assumption about what the switch answers.
        "duplex":"1.3.6.1.2.1.10.7.2.1.19"}
DUPLEX = {1:"unknown", 2:"half", 3:"full"}
HAS_DUPLEX = True     # set for real by ensure(), which asks the schema
FDB  = "1.3.6.1.2.1.17.4.3.1.2"      # dot1dTpFdbPort   (per-VLAN community)
BASE = "1.3.6.1.2.1.17.1.4.1.2"      # dot1dBasePortIfIndex

def ensure(db):
    db.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS net_ports(
      switch_ip TEXT, switch TEXT, ifindex TEXT, port TEXT, descr TEXT,
      oper TEXT, admin TEXT, speed INTEGER, duplex TEXT,
      in_err INTEGER, out_err INTEGER, crc INTEGER, out_disc INTEGER,
      mac_count INTEGER DEFAULT 0, ts INTEGER,
      PRIMARY KEY(switch_ip, ifindex));
    CREATE INDEX IF NOT EXISTS ix_ports_sw ON net_ports(switch_ip);

    CREATE TABLE IF NOT EXISTS net_port_issues(
      switch_ip TEXT, switch TEXT, ifindex TEXT, port TEXT, descr TEXT,
      severity TEXT, kind TEXT, detail TEXT,
      in_err INTEGER, out_err INTEGER, crc INTEGER, out_disc INTEGER,
      speed INTEGER, oper TEXT, ts INTEGER, diag TEXT,
      PRIMARY KEY(switch_ip, ifindex));
    CREATE INDEX IF NOT EXISTS ix_issue_sev ON net_port_issues(severity, ts);

    -- HISTORY: hourly counter snapshot per interesting port
    CREATE TABLE IF NOT EXISTS net_port_stats(
      switch_ip TEXT, ifindex TEXT, ts INTEGER,
      oper TEXT, in_err INTEGER, out_err INTEGER, crc INTEGER, out_disc INTEGER,
      PRIMARY KEY(switch_ip, ifindex, ts));
    CREATE INDEX IF NOT EXISTS ix_stats_ts ON net_port_stats(ts);

    -- CAM: what is plugged in where, right now
    CREATE TABLE IF NOT EXISTS net_cam(
      mac TEXT, switch_ip TEXT, switch TEXT, ifindex TEXT, port TEXT, vlan INTEGER, ts INTEGER,
      PRIMARY KEY(mac, switch_ip, vlan));
    CREATE INDEX IF NOT EXISTS ix_cam_sw ON net_cam(switch_ip);
    CREATE INDEX IF NOT EXISTS ix_cam_mac ON net_cam(mac);

    -- HISTORY: where a MAC has been, and when
    CREATE TABLE IF NOT EXISTS net_cam_seen(
      mac TEXT, switch_ip TEXT, port TEXT, vlan INTEGER,
      first_seen INTEGER, last_seen INTEGER,
      PRIMARY KEY(mac, switch_ip, port, vlan));
    CREATE INDEX IF NOT EXISTS ix_seen_mac ON net_cam_seen(mac, last_seen);
    CREATE INDEX IF NOT EXISTS ix_seen_last ON net_cam_seen(last_seen);

    CREATE TABLE IF NOT EXISTS net_scan_meta(k TEXT PRIMARY KEY, v TEXT);
    """)

    # self-healing migrations for DBs created before a column existed
    global HAS_DUPLEX
    for tbl, col, typ in (("net_port_issues", "diag", "TEXT"), ("net_ports", "diag", "TEXT"),
                          ("net_port_stats", "src", "TEXT"), ("net_ports", "duplex", "TEXT"),
                          # fastpoll.py writes these two; declared here as well so whichever
                          # job runs first on a fresh DB brings the column into existence
                          ("net_port_stats", "in_oct", "INTEGER"), ("net_port_stats", "out_oct", "INTEGER")):
        try: db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (tbl, col, typ))
        except Exception: pass
    # ALTER is allowed to fail (already-there is the normal case) but a lock or a
    # read-only FS looks identical. Ask the schema rather than assume, so a failed
    # migration costs one column and not the entire hourly scan.
    HAS_DUPLEX = any(r[1] == "duplex" for r in db.execute("PRAGMA table_info(net_ports)"))
    if not HAS_DUPLEX:
        print("# net_ports.duplex missing - storing ports without it", file=sys.stderr)

def mac_fmt(h): return ':'.join(h[i:i+2] for i in range(0,12,2))

def scan_ports(sw_ip, sw_name):
    data = {}
    for k, base in COLS.items():
        try: data[k] = {o[len(base)+1:]: dec(t, v) for o, t, v in walk(sw_ip, COMM, base, timeout=6)}
        except Exception: data[k] = {}
    ports, issues = [], []
    for idx, nm in (data.get("name") or {}).items():
        nm = str(nm or ""); al = str((data.get("alias") or {}).get(idx, "") or "")
        low = nm.lower()
        if low.startswith(("vl", "lo", "nu", "tu")): continue
        ie = (data.get("inerr") or {}).get(idx, 0) or 0
        oe = (data.get("outerr") or {}).get(idx, 0) or 0
        cr = (data.get("crc") or {}).get(idx, 0) or 0
        od = (data.get("outdisc") or {}).get(idx, 0) or 0
        if not all(isinstance(x, int) for x in (ie, oe, cr, od)): continue
        oper = {1:"up",2:"down",3:"testing",7:"lowerLayerDown"}.get((data.get("oper") or {}).get(idx))
        adm  = {1:"up",2:"down"}.get((data.get("admin") or {}).get(idx))
        spd  = (data.get("speed") or {}).get(idx)
        spd  = spd if isinstance(spd, int) else None
        # dot3 only answers for ethernet-like ports; anything else stays None and
        # the UI simply does not draw a duplex indicator for it. A port with no
        # link has no negotiated duplex either — whatever the MAC happens to
        # report there is not a fact about the cable, so it is discarded.
        dx   = DUPLEX.get((data.get("duplex") or {}).get(idx))
        if dx == "unknown" or oper != "up": dx = None
        d = diagnose_port(dict(port=nm, descr=al, oper=oper, admin=adm, speed=spd, duplex=dx,
                               in_err=ie, out_err=oe, crc=cr, out_disc=od, mac_count=0))
        ports.append((sw_ip, sw_name, str(idx), nm, al, oper, adm, spd, ie, oe, cr, od, _json.dumps(d), dx))
        # a bare "port is down" is not a fault worth listing - almost every switch
        # has dozens of spare ports. It still shows as the diagnosis on the port itself.
        FEED_KINDS = ("crc", "errors", "inerr", "outerr", "discards", "flapping",
                      "duplex", "halfduplex", "unplugged")
        sev = kind = detail = None
        if d and d.get("severity") not in (None, "ok") and d.get("key") in FEED_KINDS:
            sev = d["severity"]; kind = d["key"]; detail = d["title"] + " — " + d["cause"]
        if sev:
            issues.append((sw_ip, sw_name, str(idx), nm, al, sev, kind, detail, ie, oe, cr, od, spd, oper, _json.dumps(d)))
    return ports, issues

def scan_cam(sw_ip, sw_name, vlans, ifname_by_idx):
    """MAC -> port, per VLAN, using Cisco community@vlan indexing."""
    out = []
    for vl in vlans:
        c = "%s@%d" % (COMM, vl)
        try: fdb = walk(sw_ip, c, FDB, timeout=5)
        except Exception: continue
        if not fdb: continue
        try: bp = {o[len(BASE)+1:]: dec(t, v) for o, t, v in walk(sw_ip, c, BASE, timeout=5)}
        except Exception: bp = {}
        for o, t, v in fdb:
            port_no = dec(t, v)
            if not isinstance(port_no, int) or port_no == 0: continue
            octets = o[len(FDB)+1:].split(".")
            if len(octets) != 6: continue
            try: mac = mac_fmt("".join("%02x" % int(x) for x in octets))
            except Exception: continue
            idx = bp.get(str(port_no))
            nm = ifname_by_idx.get(str(idx), "") if isinstance(idx, int) else ""
            out.append((mac, sw_ip, sw_name, str(idx) if idx is not None else "", nm, vl))
    return out

def main():
    t0 = time.time()
    db = connect_durable(DB, timeout=30); ensure(db)
    sws = db.execute("SELECT ip,name FROM net_switches WHERE reachable=1").fetchall()
    vlan_map = {}
    for ip, _ in sws:
        vlan_map[ip] = [r[0] for r in db.execute(
            "SELECT vlan FROM net_vlans WHERE switch_ip=? ORDER BY vlan", (ip,))]
    now = int(time.time())

    all_ports, all_issues = [], []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(scan_ports, ip, nm): ip for ip, nm in sws}
        for f in as_completed(futs):
            try:
                p, i = f.result(); all_ports += p; all_issues += i
            except Exception as e: print("# port scan:", e, file=sys.stderr)

    ifname = {}
    for r in all_ports: ifname.setdefault(r[0], {})[r[2]] = r[3]

    all_cam = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(scan_cam, ip, nm, vlan_map.get(ip, []), ifname.get(ip, {})): ip
                for ip, nm in sws}
        for f in as_completed(futs):
            try: all_cam += f.result()
            except Exception as e: print("# cam scan:", e, file=sys.stderr)

    mac_per_port = {}
    for mac, sip, _sn, idx, _nm, _vl in all_cam:
        mac_per_port[(sip, idx)] = mac_per_port.get((sip, idx), 0) + 1

    # ── write current state ──
    db.execute("DELETE FROM net_ports")
    for r in all_ports:
        sip, sn, idx, nm, al, oper, adm, spd, ie, oe, cr, od, dg, dx = r
        base = (sip, sn, idx, nm, al, oper, adm, spd)
        rest = (ie, oe, cr, od, mac_per_port.get((sip, idx), 0), dg, now)
        if HAS_DUPLEX:
            db.execute("""INSERT OR REPLACE INTO net_ports
              (switch_ip,switch,ifindex,port,descr,oper,admin,speed,duplex,in_err,out_err,crc,out_disc,mac_count,diag,ts)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", base + (dx,) + rest)
        else:
            db.execute("""INSERT OR REPLACE INTO net_ports
              (switch_ip,switch,ifindex,port,descr,oper,admin,speed,in_err,out_err,crc,out_disc,mac_count,diag,ts)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", base + rest)
    db.execute("DELETE FROM net_port_issues")
    for r in all_issues:
        db.execute("""INSERT OR REPLACE INTO net_port_issues
          (switch_ip,switch,ifindex,port,descr,severity,kind,detail,in_err,out_err,crc,out_disc,speed,oper,diag,ts)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", r + (now,))
    db.execute("DELETE FROM net_cam")
    for mac, sip, sn, idx, nm, vl in all_cam:
        db.execute("""INSERT OR REPLACE INTO net_cam(mac,switch_ip,switch,ifindex,port,vlan,ts)
                      VALUES(?,?,?,?,?,?,?)""", (mac, sip, sn, idx, nm, vl, now))

    # ── append history ──
    for r in all_ports:
        sip, _sn, idx, _nm, _al, oper, _adm, _spd, ie, oe, cr, od, _dg, _dx = r
        if oper == "up" or ie or oe or cr or od:
            # upsert, not REPLACE: fastpoll may have written this exact
            # (switch_ip, ifindex, ts) a moment ago, and REPLACE would delete the
            # row and take its in_oct/out_oct with it
            db.execute("""INSERT INTO net_port_stats
              (switch_ip,ifindex,ts,oper,in_err,out_err,crc,out_disc,src) VALUES(?,?,?,?,?,?,?,?,'h')
              ON CONFLICT(switch_ip,ifindex,ts) DO UPDATE SET
                oper=excluded.oper, in_err=excluded.in_err, out_err=excluded.out_err,
                crc=excluded.crc, out_disc=excluded.out_disc""",
              (sip, idx, now, oper, ie, oe, cr, od))
    for mac, sip, _sn, _idx, nm, vl in all_cam:
        db.execute("""INSERT INTO net_cam_seen(mac,switch_ip,port,vlan,first_seen,last_seen)
                      VALUES(?,?,?,?,?,?)
                      ON CONFLICT(mac,switch_ip,port,vlan)
                      DO UPDATE SET last_seen=excluded.last_seen""", (mac, sip, nm, vl, now, now))

    db.execute("DELETE FROM net_port_stats WHERE (src IS NULL OR src='h') AND ts < ?", (now - KEEP_STATS_DAYS*86400,))
    db.execute("DELETE FROM net_cam_seen  WHERE last_seen < ?", (now - KEEP_SEEN_DAYS*86400,))

    meta = {"last_scan": now, "scan_ms": int((time.time()-t0)*1000),
            "switches_scanned": len(sws), "issues": len(all_issues),
            "ports": len(all_ports), "cam_entries": len(all_cam),
            "keep_days": KEEP_STATS_DAYS}
    for k, v in meta.items():
        db.execute("INSERT INTO net_scan_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                   (k, str(v)))
    db.commit(); db.close()
    print(json.dumps({"ok": True, **meta}))

if __name__ == "__main__":
    main()
