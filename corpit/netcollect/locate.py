#!/usr/bin/env python3
"""Locate + richly enrich a device on the network.
   IP|MAC -> switch/port/VLAN, live port health, throughput, PoE, reachability, reverse-DNS."""
import sys, os, sqlite3, re, json, time, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snmp2 import get, walk, dec
import socket as _sock
_sock.setdefaulttimeout(2.5)

def _community():
    v = os.environ.get("NET_SNMP_COMM")
    if v:
        return v.strip()
    # Spawned by netswitch.js (execFile), so there is no systemd
    # EnvironmentFile in scope -- read the one source of truth directly.
    try:
        with open("/etc/corpit/netcollect.env") as f:
            for line in f:
                line = line.strip()
                if line.startswith("NET_SNMP_COMM="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    sys.exit("NET_SNMP_COMM is unset and /etc/corpit/netcollect.env is unreadable.")

COMM = _community()
DB=os.environ.get("NET_DB","/var/www/corpit-hub-api/data/netfleet.db")
CORES=["10.20.224.1","10.19.224.1"]
FDB_PORT="1.3.6.1.2.1.17.4.3.1.2"; BASE_IFIDX="1.3.6.1.2.1.17.1.4.1.2"
IFNAME="1.3.6.1.2.1.31.1.1.1.1"; IFALIAS="1.3.6.1.2.1.31.1.1.1.18"
ARP_OID="1.3.6.1.2.1.4.22.1.2"
IFADMIN="1.3.6.1.2.1.2.2.1.7"; IFOPER="1.3.6.1.2.1.2.2.1.8"; IFLC="1.3.6.1.2.1.2.2.1.9"
IFSPEED="1.3.6.1.2.1.31.1.1.1.15"; IFINERR="1.3.6.1.2.1.2.2.1.14"; IFOUTERR="1.3.6.1.2.1.2.2.1.20"
IFINDISC="1.3.6.1.2.1.2.2.1.13"; IFOUTDISC="1.3.6.1.2.1.2.2.1.19"
IFHCIN="1.3.6.1.2.1.31.1.1.1.6"; IFHCOUT="1.3.6.1.2.1.31.1.1.1.10"
DOT3DUP="1.3.6.1.2.1.10.7.2.1.19"; DOT3FCS="1.3.6.1.2.1.10.7.2.1.3"
SYSUP="1.3.6.1.2.1.1.3.0"; PETH_DETECT="1.3.6.1.2.1.105.1.1.1.6"; CISCO_PWR="1.3.6.1.4.1.9.9.402.1.2.1.9"

def mac_norm(s):
    h=re.sub(r'[^0-9a-fA-F]','',s or '').lower(); return h if len(h)==12 else None
def mac_fmt(h): return ':'.join(h[i:i+2] for i in range(0,12,2))
def mac_to_oid(h): return '.'.join(str(int(h[i:i+2],16)) for i in range(0,12,2))
def phys_hex(v):
    b=v.encode('latin1') if isinstance(v,str) else v; return b.hex() if len(b)==6 else None
def db(): return sqlite3.connect(DB)
def reverse_dns(ip):
    try: return _sock.gethostbyaddr(ip)[0]
    except Exception: return None
DNS_SUFFIXES = ("", ".nrpi.local", ".corp.auction.local")
def forward_dns(name):
    for suf in DNS_SUFFIXES:
        try: return _sock.gethostbyname(name + suf)
        except Exception: pass
    return None
def g1(ip,comm,oid):
    try:
        v=get(ip,comm,oid,timeout=3)[0]; return dec(v[1],v[2])
    except Exception: return None

def vlans_cached(ip):
    try:
        d=db(); r=[x[0] for x in d.execute("SELECT vlan FROM net_vlans WHERE switch_ip=? ORDER BY vlan",(ip,))]; d.close(); return r
    except Exception: return []
def arp_cached(ip):
    try:
        d=db(); r=d.execute("SELECT mac,core FROM net_arp WHERE ip=?",(ip,)).fetchone(); d.close()
        return (mac_norm(r[0]),r[1]) if r else (None,None)
    except Exception: return (None,None)
def arp_live(target):
    for core in CORES:
        try:
            for o,t,v in walk(core,COMM,ARP_OID,timeout=5):
                if '.'.join(o.split('.')[-4:])==target:
                    mh=phys_hex(v)
                    if mh: return mh,core
        except Exception: continue
    return None,None
def if_meta(ip, ifidx):
    return (g1(ip,COMM,f"{IFNAME}.{ifidx}") or f"ifIndex {ifidx}", g1(ip,COMM,f"{IFALIAS}.{ifidx}") or "")

def find_on_switch(ip, name, macoid, vlans):
    hits=[]
    for vl in vlans:
        c=f"{COMM}@{vl}"
        port=g1(ip,c,f"{FDB_PORT}.{macoid}")
        if not isinstance(port,int) or port==0: continue
        idx=g1(ip,c,f"{BASE_IFIDX}.{port}")
        nm,al=if_meta(ip,idx) if isinstance(idx,int) else (str(idx),"")
        hits.append({"switch":name,"switch_ip":ip,"vlan":vl,"bridge_port":port,"ifindex":idx,"port":nm,"port_desc":al})
    return hits

def port_health(sw, idx, portname):
    h={}
    a=g1(sw,COMM,f"{IFADMIN}.{idx}"); o=g1(sw,COMM,f"{IFOPER}.{idx}")
    h["admin"]={1:"up",2:"down",3:"testing"}.get(a); h["oper"]={1:"up",2:"down",3:"testing",4:"unknown",5:"dormant",6:"notPresent",7:"lowerLayerDown"}.get(o)
    h["speed_mbps"]=g1(sw,COMM,f"{IFSPEED}.{idx}")
    h["duplex"]={1:"unknown",2:"half",3:"full"}.get(g1(sw,COMM,f"{DOT3DUP}.{idx}"))
    h["in_err"]=g1(sw,COMM,f"{IFINERR}.{idx}"); h["out_err"]=g1(sw,COMM,f"{IFOUTERR}.{idx}")
    h["in_disc"]=g1(sw,COMM,f"{IFINDISC}.{idx}"); h["out_disc"]=g1(sw,COMM,f"{IFOUTDISC}.{idx}")
    h["crc"]=g1(sw,COMM,f"{DOT3FCS}.{idx}")
    lc=g1(sw,COMM,f"{IFLC}.{idx}"); up=g1(sw,COMM,SYSUP)
    if isinstance(lc,int) and isinstance(up,int): h["last_change_sec"]=max(0,(up-lc))//100
    # live throughput (2 samples, ~2s)
    i1=g1(sw,COMM,f"{IFHCIN}.{idx}"); o1=g1(sw,COMM,f"{IFHCOUT}.{idx}"); time.sleep(2)
    i2=g1(sw,COMM,f"{IFHCIN}.{idx}"); o2=g1(sw,COMM,f"{IFHCOUT}.{idx}")
    if all(isinstance(x,int) for x in (i1,o1,i2,o2)):
        bi=(i2-i1)*8/2.0; bo=(o2-o1)*8/2.0
        h["in_mbps"]=round(bi/1e6,2); h["out_mbps"]=round(bo/1e6,2)
        if h.get("speed_mbps"): h["util_pct"]=round(max(bi,bo)/1e6/h["speed_mbps"]*100,1)
    # PoE (parse Gi<mod>/0/<port> -> group.port)
    m=re.search(r'(\d+)/\d+/(\d+)', portname or '')
    if m:
        grp,prt=m.group(1),m.group(2)
        h["poe_status"]={1:"disabled",2:"searching",3:"delivering",4:"fault",5:"test",6:"otherFault"}.get(g1(sw,COMM,f"{PETH_DETECT}.{grp}.{prt}"))
        mw=g1(sw,COMM,f"{CISCO_PWR}.{grp}.{prt}")
        if isinstance(mw,int) and mw>0: h["poe_watts"]=round(mw/1000.0,1)
    return h

# Most endpoints drop ICMP (macOS and Windows firewalls block it by default), so a
# failed ping proves nothing. These signals need no cooperation from the host:
#   arp   - the router answered for this IP recently => the device replied to ARP
#   cam   - a switch learned its MAC recently       => the device is transmitting
#   tcp   - a connect that succeeds OR is refused   => the host is up and answering
TCP_PORTS = (445, 3389, 22, 5900, 80, 443, 62078)

def tcp_probe(ip, ports=TCP_PORTS, timeout=0.6):
    """A refused connection is as good as an accepted one: something answered."""
    for port in ports:
        s2 = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s2.settimeout(timeout)
        try:
            s2.connect((ip, port)); s2.close()
            return {"alive": True, "port": port, "how": "open"}
        except ConnectionRefusedError:
            s2.close(); return {"alive": True, "port": port, "how": "refused"}
        except Exception:
            pass
        finally:
            try: s2.close()
            except Exception: pass
    return {"alive": False}

def arp_age(ip):
    try:
        d = db(); r = d.execute("SELECT ts FROM net_arp WHERE ip=?", (ip,)).fetchone(); d.close()
        return int(time.time()) - r[0] if r else None
    except Exception: return None

def cam_age(mac):
    try:
        d = db()
        r = d.execute("SELECT MAX(last_seen) FROM net_cam_seen WHERE mac=?", (mac,)).fetchone()
        d.close()
        return int(time.time()) - r[0] if r and r[0] else None
    except Exception: return None

def ping(ip):
    try:
        out=subprocess.run(["ping","-c","2","-W","1",ip],capture_output=True,text=True,timeout=6).stdout
        m=re.search(r'(\d+)% packet loss',out); loss=int(m.group(1)) if m else 100
        r=re.search(r'=\s*[\d.]+/([\d.]+)/',out)
        return {"alive":loss<100,"loss_pct":loss,"rtt_ms":round(float(r.group(1)),1) if r else None}
    except Exception: return {"alive":False,"loss_pct":100,"rtt_ms":None}
def gateway_of(ip):
    p=ip.split('.'); return '.'.join(p[:3]+['1']) if len(p)==4 else None

def switches():
    d=db(); rows=d.execute("SELECT ip,name FROM net_switches WHERE reachable=1 ORDER BY core DESC,name").fetchall(); d.close(); return rows

def locate(q):
    q=(q or '').strip(); res={"query":q}
    mac=mac_norm(q)
    if not mac and re.match(r'^\d+\.\d+\.\d+\.\d+$',q):
        res["input_type"]="ip"; res["ip"]=q
        m,core=arp_cached(q)
        if m: res["arp_source"]="cache"
        else: m,core=arp_live(q); res["arp_source"]="live"
        if not m: res["error"]="no ARP entry — device offline or not L3-active"
        else: mac=m; res["arp_from_core"]=core
    elif mac:
        res["input_type"]="mac"
        d=db(); row=d.execute("SELECT ip FROM net_arp WHERE mac=?",(mac_fmt(mac),)).fetchone(); d.close()
        if row: res["ip"]=row[0]
    else:
        # a device name from inventory - resolve it forward, then trace as an IP
        ip6=forward_dns(q)
        if not ip6:
            res["input_type"]="host"
            res["error"]="No DNS record for that device name - it may be off the domain, renamed, or powered off"
            res["ok"]=False; return res
        res["input_type"]="host"; res["ip"]=ip6; res["resolved_from"]=q
        m,core=arp_cached(ip6)
        if m: res["arp_source"]="cache"
        else: m,core=arp_live(ip6); res["arp_source"]="live"
        if not m: res["error"]="Resolved to "+ip6+" but no ARP entry - the device is probably powered off"
        else: mac=m; res["arp_from_core"]=core
    if mac:
        res["mac"]=mac_fmt(mac)
        if res.get("ip"): res["hostname"]=reverse_dns(res["ip"])
        macoid=mac_to_oid(mac); hits=[]
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs=[ex.submit(find_on_switch,ip,name,macoid,vlans_cached(ip)) for ip,name in switches()]
            for f in as_completed(futs): hits+=f.result()
        for h in hits:
            p=(h["port"] or "").lower()
            h["role"]="uplink" if any(k in p for k in ("po","port-channel","te","twe","fo","hu","uplink")) else "edge"
        hits.sort(key=lambda h:(h["role"]!="edge",h["switch"],h["vlan"]))
        res["locations"]=hits
        edge=next((h for h in hits if h["role"]=="edge"),None)
        res["edge"]=edge
        # ── enrich in parallel: port health + reachability ──
        tasks={}
        with ThreadPoolExecutor(max_workers=4) as ex:
            if edge and isinstance(edge.get("ifindex"),int):
                tasks["ph"]=ex.submit(port_health, edge["switch_ip"], edge["ifindex"], edge["port"])
            if res.get("ip"):
                gw=gateway_of(res["ip"])
                tasks["dev"]=ex.submit(ping,res["ip"])
                tasks["tcp"]=ex.submit(tcp_probe,res["ip"])
                if gw: tasks["gw"]=ex.submit(ping,gw)
            for k,f in tasks.items(): tasks[k]=f.result()
        if edge and "ph" in tasks: edge["health"]=tasks["ph"]
        if "dev" in tasks:
            dev = tasks["dev"]
            tcp = tasks.get("tcp") or {}
            aage = arp_age(res.get("ip")) if res.get("ip") else None
            cage = cam_age(mac) if mac else None
            # believed present if ANY signal says so - ICMP is the least reliable
            present = bool(dev.get("alive")) or bool(tcp.get("alive")) \
                      or (aage is not None and aage < 900) or (cage is not None and cage < 900)
            how = ("ICMP" if dev.get("alive") else
                   ("TCP :%s" % tcp.get("port") if tcp.get("alive") else
                    ("ARP %dm ago" % (aage//60) if aage is not None and aage < 900 else
                     ("switch saw it %dm ago" % (cage//60) if cage is not None and cage < 900 else None))))
            dev = dict(dev)
            dev.update(present=present, evidence=how, icmp=dev.get("alive"),
                       tcp=tcp.get("alive"), tcp_port=tcp.get("port"), tcp_how=tcp.get("how"),
                       arp_age_s=aage, cam_age_s=cage)
            res["reachability"]={"device":dev}
            if "gw" in tasks: res["reachability"]["gateway"]=dict(ip=gateway_of(res["ip"]),**tasks["gw"])
    res["ok"]=not res.get("error")
    return res

if __name__=="__main__":
    print(json.dumps(locate(sys.argv[1] if len(sys.argv)>1 else ""), default=str))
