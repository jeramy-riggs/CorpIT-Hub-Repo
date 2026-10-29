#!/usr/bin/env python3
"""
corpit-netcollect: poll the Cisco switch fleet via SNMP RO and cache to SQLite.
Reads nothing sensitive; writes /var/www/corpit-hub-api/data/netfleet.db for the
/api/netswitch route to serve. Pure-Python SNMPv2c (no net-snmp dependency).
"""
from corpit_sqlite import connect_durable
import sys, os, sqlite3, json, time, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snmp2 import get, walk, dec

COMM = os.environ.get("NET_SNMP_COMM")
if not COMM:
    sys.exit("NET_SNMP_COMM is unset. The SNMP RO community is supplied by "
             "/etc/corpit/netcollect.env (systemd EnvironmentFile); it is deliberately "
             "not defaulted in source.")
SEEDS  = os.environ.get("NET_SEEDS", "10.20.224.1,10.19.224.1").split(",")
DBPATH = os.environ.get("NET_DB", "/var/www/corpit-hub-api/data/netfleet.db")
NEWEST = "17.15.4"

SYS = dict(name="1.3.6.1.2.1.1.5.0", descr="1.3.6.1.2.1.1.1.0",
           loc="1.3.6.1.2.1.1.6.0", uptime="1.3.6.1.2.1.1.3.0")
CDP_ID="1.3.6.1.4.1.9.9.23.1.2.1.1.6"; CDP_ADDR="1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_PLAT="1.3.6.1.4.1.9.9.23.1.2.1.1.8"
ENT_MODEL="1.3.6.1.2.1.47.1.1.1.1.13"; ENT_SER="1.3.6.1.2.1.47.1.1.1.1.11"
IF_OPER="1.3.6.1.2.1.2.2.1.8"
ARP_OID="1.3.6.1.2.1.4.22.1.2"          # ipNetToMediaPhysAddress
VTP_STATE="1.3.6.1.4.1.9.9.46.1.3.1.1.2"  # vtpVlanState

def phys_hex(v):
    b=v.encode("latin1") if isinstance(v,str) else v
    return b.hex() if len(b)==6 else None

def collect_arp(core):
    out=[]
    for o,t,v in walk(core,COMM,ARP_OID,timeout=6):
        ip=".".join(o.split(".")[-4:]); mh=phys_hex(v)
        if mh and ip.count(".")==3: out.append((ip,":".join(mh[i:i+2] for i in range(0,12,2)),core))
    return out

def collect_vlans(ip):
    out=[]
    for o,t,v in walk(ip,COMM,VTP_STATE,timeout=4):
        vl=int(o.split(".")[-1])
        if dec(t,v)==1 and vl<1002: out.append(vl)
    return out

def hex2ip(h):
    try:
        b=bytes.fromhex(h)
        if len(b)==4: return ".".join(str(x) for x in b)
    except Exception: pass
    return None

def first_nonempty(ip, base):
    for o,t,v in walk(ip, COMM, base, timeout=4):
        s=dec(t,v)
        if s not in (None,"",b""): return s
    return None

def poll(ip):
    r={"ip":ip,"reachable":0}
    try:
        g={k:dec(*get(ip,COMM,oid,timeout=4)[0][1:]) for k,oid in SYS.items()}
        name=(g["name"] or "").replace(".corp.auction.local","")
        descr=(g["descr"] or "").split("\n")[0].strip()
        ver=descr.split("Version ")[1].split(" ")[0].rstrip(",").strip() if "Version " in descr else "?"
        oper=walk(ip, COMM, IF_OPER, timeout=4)
        up=sum(1 for _,t,v in oper if dec(t,v)==1)
        r.update(reachable=1, name=name, site=name.split("-")[0], descr=descr,
                 location=g["loc"], uptime_days=round((g["uptime"] or 0)/100/86400,1),
                 ios=ver, model=first_nonempty(ip,ENT_MODEL), serial=first_nonempty(ip,ENT_SER),
                 if_total=len(oper), if_up=up, core=1 if "COR" in name else 0)
    except socket.timeout:
        r["error"]="timeout"
    except Exception as e:
        r["error"]=str(e)
    return r

def discover(seed):
    nb={}
    ids=walk(seed, COMM, CDP_ID, timeout=4)
    addrs={o[len(CDP_ADDR)+1:]:dec(t,v) for o,t,v in walk(seed, COMM, CDP_ADDR, timeout=4)}
    plats={o[len(CDP_PLAT)+1:]:dec(t,v) for o,t,v in walk(seed, COMM, CDP_PLAT, timeout=4)}
    for o,t,v in ids:
        idx=o[len(CDP_ID)+1:]
        ip=hex2ip(addrs.get(idx,"") or "")
        plat=plats.get(idx,"") or ""
        if ip: nb.setdefault(ip, plat)
    return nb

def is_switch(plat, seed=False):
    if seed: return True
    p=(plat or "").lower()
    return any(k in p for k in ("cat","c9","ws-c","switch"))

def ensure_schema(db):
    db.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS net_switches(
      ip TEXT PRIMARY KEY, name TEXT, site TEXT, model TEXT, serial TEXT,
      ios TEXT, uptime_days REAL, if_total INTEGER, if_up INTEGER,
      core INTEGER, location TEXT, reachable INTEGER, ios_current INTEGER,
      last_seen INTEGER, error TEXT);
    CREATE TABLE IF NOT EXISTS net_meta(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS net_samples(
      ip TEXT, ts INTEGER, if_up INTEGER, if_total INTEGER);
    CREATE INDEX IF NOT EXISTS ix_samples ON net_samples(ip, ts);
    CREATE TABLE IF NOT EXISTS net_arp(ip TEXT PRIMARY KEY, mac TEXT, core TEXT, ts INTEGER);
    CREATE INDEX IF NOT EXISTS ix_arp_mac ON net_arp(mac);
    CREATE TABLE IF NOT EXISTS net_arp_seen(
      ip TEXT, mac TEXT, first_seen INTEGER, last_seen INTEGER,
      PRIMARY KEY(ip, mac));
    CREATE INDEX IF NOT EXISTS ix_arpseen_mac ON net_arp_seen(mac, last_seen);
    CREATE INDEX IF NOT EXISTS ix_arpseen_last ON net_arp_seen(last_seen);
    CREATE TABLE IF NOT EXISTS net_vlans(switch_ip TEXT, vlan INTEGER, ts INTEGER, PRIMARY KEY(switch_ip,vlan));
    """)

def main():
    t0=time.time()
    fleet={ip:{"plat":"seed-core","seed":True} for ip in SEEDS}
    for s in SEEDS:
        try:
            for ip,plat in discover(s).items():
                fleet.setdefault(ip, {"plat":plat,"seed":False})
        except Exception as e:
            print(f"# discover {s}: {e}", file=sys.stderr)
    targets=[ip for ip,m in fleet.items() if is_switch(m["plat"], m["seed"])]
    results=[]
    with ThreadPoolExecutor(max_workers=8) as ex:
        for f in as_completed({ex.submit(poll,ip):ip for ip in targets}):
            results.append(f.result())

    # ARP and VLAN walks are network I/O. Do them before opening the write
    # transaction so the hub's writes (watch, claim) are not locked out for
    # the whole SNMP run.
    arp_rows=[]
    for core in SEEDS:
        try: arp_rows.extend(list(collect_arp(core)))
        except Exception as e: print(f"# arp {core}: {e}", file=sys.stderr)
    reach_ips=[r["ip"] for r in results if r.get("reachable")]
    with ThreadPoolExecutor(max_workers=8) as ex:
        vmap=dict(zip(reach_ips, ex.map(lambda i: collect_vlans(i), reach_ips)))

    os.makedirs(os.path.dirname(DBPATH), exist_ok=True)
    db=connect_durable(DBPATH); ensure_schema(db)
    now=int(time.time())
    for r in results:
        if not r.get("reachable"):
            db.execute("UPDATE net_switches SET reachable=0, error=? WHERE ip=?",
                       (r.get("error"), r["ip"])); continue
        cur=1 if r["ios"]==NEWEST else 0
        db.execute("""INSERT INTO net_switches
          (ip,name,site,model,serial,ios,uptime_days,if_total,if_up,core,location,reachable,ios_current,last_seen,error)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)
          ON CONFLICT(ip) DO UPDATE SET name=excluded.name,site=excluded.site,model=excluded.model,
            serial=excluded.serial,ios=excluded.ios,uptime_days=excluded.uptime_days,
            if_total=excluded.if_total,if_up=excluded.if_up,core=excluded.core,location=excluded.location,
            reachable=1,ios_current=excluded.ios_current,last_seen=excluded.last_seen,error=NULL""",
          (r["ip"],r["name"],r["site"],r["model"],r["serial"],r["ios"],r["uptime_days"],
           r["if_total"],r["if_up"],r["core"],r["location"],1,cur,now))
        db.execute("INSERT INTO net_samples(ip,ts,if_up,if_total) VALUES(?,?,?,?)",
                   (r["ip"],now,r["if_up"],r["if_total"]))
    db.execute("DELETE FROM net_samples WHERE ts < ?", (now-7*86400,))  # keep 7d
    # ARP cache (IP<->MAC) from cores
    for ip,mac,c in arp_rows:
        db.execute("INSERT INTO net_arp(ip,mac,core,ts) VALUES(?,?,?,?) "
                   "ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac,core=excluded.core,ts=excluded.ts",
                   (ip,mac,c,now))
        db.execute("INSERT INTO net_arp_seen(ip,mac,first_seen,last_seen) VALUES(?,?,?,?) "
                   "ON CONFLICT(ip,mac) DO UPDATE SET last_seen=excluded.last_seen",
                   (ip,mac,now,now))
    db.execute("DELETE FROM net_arp WHERE ts < ?", (now-3600,))
    db.execute("DELETE FROM net_arp_seen WHERE last_seen < ?", (now-30*86400,))
    # per-switch VLAN cache (reachable switches, walked above)
    for sip,vls in vmap.items():
        for vl in vls:
            db.execute("INSERT INTO net_vlans(switch_ip,vlan,ts) VALUES(?,?,?) "
                       "ON CONFLICT(switch_ip,vlan) DO UPDATE SET ts=excluded.ts",(sip,vl,now))
    db.execute("DELETE FROM net_vlans WHERE ts < ?", (now-3600,))
    reach=sum(1 for r in results if r.get("reachable"))
    meta={"last_run":now,"run_ms":int((time.time()-t0)*1000),
          "device_count":len(results),"reachable":reach,
          "seeds":",".join(SEEDS),"community_ok":1 if reach else 0}
    for k,v in meta.items():
        db.execute("INSERT INTO net_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(k,str(v)))
    db.commit(); db.close()
    print(json.dumps({"ok":True,**meta,"db":DBPATH}))

if __name__=="__main__":
    main()
