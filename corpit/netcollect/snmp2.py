#!/usr/bin/env python3
import socket, sys

def ber_len(n):
    if n < 0x80: return bytes([n])
    b=[]
    while n: b.insert(0,n&0xff); n>>=8
    return bytes([0x80|len(b)])+bytes(b)
def tlv(t,v): return bytes([t])+ber_len(len(v))+v
def enc_int(n):
    if n==0: return tlv(0x02,b'\x00')
    b=[]; v=n
    while v: b.insert(0,v&0xff); v>>=8
    if b[0]&0x80: b.insert(0,0)
    return tlv(0x02,bytes(b))
def enc_oid(o):
    p=[int(x) for x in o.split('.')]; body=bytes([p[0]*40+p[1]])
    for x in p[2:]:
        if x<0x80: body+=bytes([x])
        else:
            s=[x&0x7f]; x>>=7
            while x: s.insert(0,(x&0x7f)|0x80); x>>=7
            body+=bytes(s)
    return tlv(0x06,body)
def rd_len(d,i):
    l=d[i]; i+=1
    if l<0x80: return l,i
    n=l&0x7f; return int.from_bytes(d[i:i+n],'big'), i+n
def parse_tlvs(d):
    out=[]; i=0
    while i < len(d):
        tag=d[i]; ln,j=rd_len(d,i+1); out.append((tag,d[j:j+ln])); i=j+ln
    return out
def oid_str(val):
    p=[val[0]//40, val[0]%40]; x=0
    for b in val[1:]:
        x=(x<<7)|(b&0x7f)
        if not b&0x80: p.append(x); x=0
    return '.'.join(map(str,p))
def dec(tag,val):
    if tag==0x04:
        try: return val.decode()
        except: return val.hex()
    if tag in (0x02,0x41,0x42,0x43,0x46,0x47): return int.from_bytes(val,'big')
    if tag==0x06: return oid_str(val)
    if tag==0x40: return '.'.join(str(b) for b in val)  # IpAddress
    if tag==0x05: return None
    return val.hex()

def _req(host,comm,pdu_tag,oid,timeout,reqid):
    vb=tlv(0x30, enc_oid(oid)+tlv(0x05,b''))
    pdu=tlv(pdu_tag, enc_int(reqid)+enc_int(0)+enc_int(0)+tlv(0x30,vb))
    msg=tlv(0x30, enc_int(1)+tlv(0x04,comm.encode())+pdu)
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(timeout)
    s.sendto(msg,(host,161)); data,_=s.recvfrom(65535); s.close()
    top=parse_tlvs(data)[0]; inner=parse_tlvs(top[1])
    pduf=[t for t in inner if (t[0]&0xE0)==0xA0][0]
    f=parse_tlvs(pduf[1]); vbs=parse_tlvs(f[3][1])
    out=[]
    for _,vbv in vbs:
        it=parse_tlvs(vbv); out.append((oid_str(it[0][1]), it[1][0], it[1][1]))
    return out
def get(host,comm,oid,timeout=5,reqid=0x2A2A):
    return _req(host,comm,0xA0,oid,timeout,reqid)
def walk(host,comm,base,timeout=5,limit=4000):
    cur=base; res=[]; rid=0x1000
    while True:
        rid+=1
        try: r=_req(host,comm,0xA1,cur,timeout,rid)
        except socket.timeout: break
        if not r: break
        oid,tag,val=r[0]
        if not (oid==base or oid.startswith(base+'.')): break
        if tag==0x80 or tag==0x82: break  # endOfMibView/noSuchObject
        res.append((oid,tag,val)); cur=oid
        if len(res)>=limit: break
    return res

if __name__=='__main__':
    mode=sys.argv[1]; host=sys.argv[2]; comm=sys.argv[3]
    if mode=='get':
        for oid in sys.argv[4:]:
            try:
                for o,t,v in get(host,comm,oid): print(f"{oid} = {dec(t,v)}")
            except socket.timeout: print(f"{oid} = TIMEOUT")
            except Exception as e: print(f"{oid} = ERR {e}")
    elif mode=='walk':
        for base in sys.argv[4:]:
            r=walk(host,comm,base)
            print(f"# {base}: {len(r)} rows")
            for o,t,v in r:
                suffix=o[len(base)+1:]
                print(f"  {suffix} = {dec(t,v)}")
