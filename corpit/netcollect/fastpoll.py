#!/usr/bin/env python3
"""
fastpoll.py — 15-minute counter sampling across every live port.

The hourly sweep is for inventory (CAM, models, descriptions). It is far too
coarse to chase a fault someone reports "around 2pm". This job samples only the
cheap error/traffic counters, so it can run every 15 minutes and give a week of
fine-grained history for any port, without anyone having to pin it first.

Retention is tiered, written as `src` on each row:
  q  15-minute samples   kept  7 days   (the "what happened this week" view)
  h  hourly samples      kept 30 days   (written by healthscan.py)
Watched items are sampled every 5 minutes by watchpoll.py and kept 120 days.
"""
from corpit_sqlite import connect_durable
import sys, os, sqlite3, time, json
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snmp2 import walk, dec

COMM = os.environ.get("NET_SNMP_COMM")
if not COMM:
    sys.exit("NET_SNMP_COMM is unset. The SNMP RO community is supplied by "
             "/etc/corpit/netcollect.env (systemd EnvironmentFile); it is deliberately "
             "not defaulted in source.")
DB   = os.environ.get("NET_DB", "/var/www/corpit-hub-api/data/netfleet.db")
KEEP_Q_DAYS = int(os.environ.get("NET_KEEP_Q_DAYS", "7"))
KEEP_H_DAYS = int(os.environ.get("NET_KEEP_H_DAYS", "30"))

# deliberately few columns — name/alias/speed change rarely and come from the hourly scan
COLS = {"oper":"1.3.6.1.2.1.2.2.1.8",
        "inerr":"1.3.6.1.2.1.2.2.1.14",
        "outerr":"1.3.6.1.2.1.2.2.1.20",
        "crc":"1.3.6.1.2.1.10.7.2.1.3",
        "outdisc":"1.3.6.1.2.1.2.2.1.19",
        # 64-bit octet counters. Stored raw; the delta between two consecutive
        # samples is what turns into a throughput figure, so a single sample on
        # its own is deliberately useless and never shown as a rate.
        "inoct":"1.3.6.1.2.1.31.1.1.1.6",
        "outoct":"1.3.6.1.2.1.31.1.1.1.10"}

def ensure(db):
    db.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS net_port_stats(
      switch_ip TEXT, ifindex TEXT, ts INTEGER,
      oper TEXT, in_err INTEGER, out_err INTEGER, crc INTEGER, out_disc INTEGER,
      in_oct INTEGER, out_oct INTEGER,
      PRIMARY KEY(switch_ip, ifindex, ts));
    CREATE INDEX IF NOT EXISTS ix_stats_ts ON net_port_stats(ts);
    """)
    for col, typ in (("src", "TEXT"), ("in_oct", "INTEGER"), ("out_oct", "INTEGER")):
        try: db.execute("ALTER TABLE net_port_stats ADD COLUMN %s %s" % (col, typ))
        except Exception: pass
    db.execute("CREATE INDEX IF NOT EXISTS ix_stats_src ON net_port_stats(src, ts)")
    # the throughput query filters (switch_ip, ts); the PK autoindex puts ifindex
    # between them, so ts is not reachable as a prefix without this
    db.execute("CREATE INDEX IF NOT EXISTS ix_stats_sw_ts ON net_port_stats(switch_ip, ts)")

def scan(sw_ip, keep):
    """keep: set of ifindexes worth sampling (up, or previously erroring)."""
    data = {}
    for k, base in COLS.items():
        try: data[k] = {o[len(base)+1:]: dec(t, v) for o, t, v in walk(sw_ip, COMM, base, timeout=6)}
        except Exception: data[k] = {}
    out = []
    for idx, o in (data.get("oper") or {}).items():
        if keep and idx not in keep: continue
        oper = {1:"up",2:"down",3:"testing",7:"lowerLayerDown"}.get(o)
        ie = (data.get("inerr") or {}).get(idx, 0) or 0
        oe = (data.get("outerr") or {}).get(idx, 0) or 0
        cr = (data.get("crc") or {}).get(idx, 0) or 0
        od = (data.get("outdisc") or {}).get(idx, 0) or 0
        if not all(isinstance(x, int) for x in (ie, oe, cr, od)): continue
        # octets are optional: a switch that does not answer the 64-bit counters
        # still gets its error sampling, it just never grows a throughput figure
        io = (data.get("inoct") or {}).get(idx)
        oo = (data.get("outoct") or {}).get(idx)
        if not isinstance(io, int): io = None
        if not isinstance(oo, int): oo = None
        # only store ports that are carrying or have carried something
        if oper != "up" and not (ie or oe or cr or od): continue
        out.append((sw_ip, idx, oper, ie, oe, cr, od, io, oo))
    return out

def main():
    t0 = time.time()
    db = connect_durable(DB, timeout=30); ensure(db)
    sws = db.execute("SELECT ip FROM net_switches WHERE reachable=1").fetchall()
    # sample what the last full scan showed as interesting — keeps this job cheap
    keep = {}
    try:
        for sip, idx in db.execute(
            "SELECT switch_ip, ifindex FROM net_ports WHERE oper='up' OR in_err>0 OR out_err>0 OR crc>0"):
            keep.setdefault(sip, set()).add(idx)
    except Exception:
        keep = {}
    now = int(time.time())

    rows = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(scan, ip, keep.get(ip, set())): ip for (ip,) in sws}
        for f in as_completed(futs):
            try: rows += f.result()
            except Exception as e: print("# fastpoll:", e, file=sys.stderr)

    for sip, idx, oper, ie, oe, cr, od, io, oo in rows:
        db.execute("""INSERT INTO net_port_stats
          (switch_ip,ifindex,ts,oper,in_err,out_err,crc,out_disc,in_oct,out_oct,src)
          VALUES(?,?,?,?,?,?,?,?,?,?,'q')
          ON CONFLICT(switch_ip,ifindex,ts) DO UPDATE SET
            oper=excluded.oper, in_err=excluded.in_err, out_err=excluded.out_err,
            crc=excluded.crc, out_disc=excluded.out_disc,
            in_oct=excluded.in_oct, out_oct=excluded.out_oct, src='q'""",
          (sip, idx, now, oper, ie, oe, cr, od, io, oo))

    db.execute("DELETE FROM net_port_stats WHERE src='q' AND ts < ?", (now - KEEP_Q_DAYS*86400,))
    db.execute("DELETE FROM net_port_stats WHERE (src IS NULL OR src='h') AND ts < ?",
               (now - KEEP_H_DAYS*86400,))
    db.commit()
    total = db.execute("SELECT COUNT(*) FROM net_port_stats").fetchone()[0]
    db.close()
    print(json.dumps({"ok": True, "switches": len(sws), "sampled": len(rows),
                      "run_ms": int((time.time()-t0)*1000), "rows_total": total,
                      "keep_q_days": KEEP_Q_DAYS, "keep_h_days": KEEP_H_DAYS}))

if __name__ == "__main__":
    main()
