#!/usr/bin/env python3
"""Explicit selected-target probes. No DNS, gateway guessing, scans, SETs or cache writes."""
import argparse
import concurrent.futures
import ipaddress
import json
import os
import pwd
import re
import socket
import subprocess
import sys


def private_ip(value):
    try:
        ip = ipaddress.IPv4Address(value)
        return str(ip) if any(ip in ipaddress.ip_network(c) for c in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')) else None
    except ValueError:
        return None


def dev_tcp22_blocked():
    """Explicit DEV policy, enabled only for the service UID covered by its guard.

    The DEV-only setting mirrors the nft rule checked at installation. It does
    not infer a local block from ECONNREFUSED or change any firewall rule.
    """
    if os.environ.get('IDENTITY_DEV_TCP22_BLOCKED') != '1' or socket.gethostname() != 'itam':
        return False
    try:
        return os.geteuid() == pwd.getpwnam('corpit').pw_uid
    except KeyError:
        return False


def reachability(ip):
    def icmp():
        try:
            r = subprocess.run(['ping', '-n', '-c', '2', '-W', '1', ip], capture_output=True, text=True, timeout=6)
            loss = re.search(r'(\d+(?:\.\d+)?)% packet loss', r.stdout)
            timing = re.search(r'=\s*[\d.]+/([\d.]+)/', r.stdout)
            return {'status': 'responded' if r.returncode == 0 else 'no_reply' if r.returncode == 1 else 'unavailable',
                    'lossPct': float(loss.group(1)) if loss else None, 'rttMs': float(timing.group(1)) if timing else None}
        except Exception:
            return {'status': 'unavailable', 'lossPct': None, 'rttMs': None}

    def tcp():
        observations = []
        blocked_tcp22 = dev_tcp22_blocked()
        for port in (445, 3389, 22, 5900, 80, 443):
            if port == 22 and blocked_tcp22:
                observations.append({'port': port, 'status': 'locally_blocked', 'source': 'local_policy',
                                     'reason': 'DEV egress guard blocks outbound TCP 22; endpoint was not probed.'})
                continue
            try:
                with socket.create_connection((ip, port), timeout=0.6):
                    observations.append({'port': port, 'status': 'open'})
            except ConnectionRefusedError:
                observations.append({'port': port, 'status': 'refused'})
            except (TimeoutError, socket.timeout):
                observations.append({'port': port, 'status': 'no_reply'})
            except OSError:
                observations.append({'port': port, 'status': 'unavailable'})
        return observations

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        ping_task = executor.submit(icmp)
        tcp_task = executor.submit(tcp)
        return {'status': 'ok', 'ip': ip, 'icmp': ping_task.result(), 'tcp': tcp_task.result(),
                'note': 'A response identifies this IP at probe time, not the hardware. No response does not establish offline state.'}


def snmp_reader(ip):
    # Reuse the deployed SNMP library and read-only community source. Do not call locate().
    sys.path.insert(0, '/opt/corpit-netcollect')
    from snmp2 import get, dec
    community = os.environ.get('NET_SNMP_COMM', '').strip()
    if not community:
        try:
            with open('/etc/corpit/netcollect.env') as source:
                for line in source:
                    if line.strip().startswith('NET_SNMP_COMM='):
                        community = line.strip().split('=', 1)[1].strip().strip('"').strip("'")
                        break
        except OSError:
            pass
    if not community:
        return {'status': 'unavailable', 'reason': 'Read-only SNMP configuration is unavailable'}

    def read(oid, suffix=''):
        try:
            values = get(ip, community + suffix, oid, timeout=2)
            return dec(values[0][1], values[0][2]) if values else None
        except Exception:
            return None

    return read


def switch_port(ip, mac, vlan, ifindex, read=None):
    read = read or snmp_reader(ip)
    if not callable(read):
        return read
    macoid = '.'.join(str(int(v, 16)) for v in mac.split(':'))
    port = read('1.3.6.1.2.1.17.4.3.1.2.' + macoid, '@' + str(vlan))
    if port is None:
        return {'status': 'unavailable', 'reason': 'The selected switch did not return a usable MAC-table value'}
    if not isinstance(port, int) or port <= 0:
        return {'status': 'empty', 'reason': 'No MAC-table observation on this switch/VLAN; no offline determination'}
    current = read('1.3.6.1.2.1.17.1.4.1.2.' + str(port), '@' + str(vlan))
    if current != ifindex:
        return {'status': 'changed' if isinstance(current, int) else 'unavailable', 'observedIfindex': current,
                'reason': 'The MAC-table interface did not verify the selected cached port; no other port was chosen'}
    oids = {'port': '1.3.6.1.2.1.31.1.1.1.1', 'description': '1.3.6.1.2.1.31.1.1.1.18',
            'admin': '1.3.6.1.2.1.2.2.1.7', 'oper': '1.3.6.1.2.1.2.2.1.8',
            'speedMbps': '1.3.6.1.2.1.31.1.1.1.15', 'duplex': '1.3.6.1.2.1.10.7.2.1.19',
            'inErrors': '1.3.6.1.2.1.2.2.1.14', 'outErrors': '1.3.6.1.2.1.2.2.1.20',
            'inDiscards': '1.3.6.1.2.1.2.2.1.13', 'outDiscards': '1.3.6.1.2.1.2.2.1.19',
            'crc': '1.3.6.1.2.1.10.7.2.1.3'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {key: executor.submit(read, oid + '.' + str(ifindex)) for key, oid in oids.items()}
        values = {key: f.result() for key, f in futures.items()}
    return {'status': 'partial' if any(v is None for v in values.values()) else 'ok', 'switchIp': ip,
            'ifindex': ifindex, 'vlan': vlan, 'mac': mac, 'values': values,
            'note': 'Exact MAC-table and port reads only. Uplink observations do not establish an endpoint edge port. Counters are totals.'}



def normalized_port(value):
    value = str(value or '').strip().lower()
    for long_name, short in [('tengigabitethernet', 'te'), ('twentyfivegige', 'twe'),
                              ('gigabitethernet', 'gi'), ('fastethernet', 'fa'),
                              ('fortygigabitethernet', 'fo'), ('hundredgige', 'hu'), ('ethernet', 'eth')]:
        if value.startswith(long_name):
            return short + value[len(long_name):]
    return value


def same_system(a, b):
    a, b = str(a or '').lower().rstrip('.'), str(b or '').lower().rstrip('.')
    return bool(a and b and (a == b or ('.' not in a or '.' not in b) and a.split('.')[0] == b.split('.')[0]))


def current_ap_port(ip, mac, vlan, expected_port, expected_system):
    read = snmp_reader(ip)
    if not callable(read):
        return read
    name = read('1.3.6.1.2.1.1.5.0')
    if not same_system(name, expected_system):
        return {'status': 'unavailable', 'reason': 'Live switch identity did not match the AP neighbor; health withheld'}
    macoid = '.'.join(str(int(v, 16)) for v in mac.split(':'))
    bridge = read('1.3.6.1.2.1.17.4.3.1.2.' + macoid, '@' + str(vlan))
    if bridge is None:
        return {'status': 'unavailable', 'reason': 'The AP switch MAC table could not be read'}
    if not isinstance(bridge, int) or bridge <= 0:
        return {'status': 'empty', 'reason': 'Selected MAC was not found on the AP switch/VLAN candidate; no offline determination'}
    index = read('1.3.6.1.2.1.17.1.4.1.2.' + str(bridge), '@' + str(vlan))
    if not isinstance(index, int) or not 1 <= index <= 2147483647:
        return {'status': 'unavailable', 'reason': 'The live bridge port did not resolve to a valid interface'}
    port = read('1.3.6.1.2.1.31.1.1.1.1.' + str(index))
    if normalized_port(port) != normalized_port(expected_port):
        return {'status': 'changed', 'observedPort': port, 'observedIfindex': index,
                'reason': 'The selected MAC is on a different port from the current AP neighbor; health withheld'}
    # Reverify the same MAC/index before health, then verify the returned port name.
    result = switch_port(ip, mac, vlan, index, read=read)
    if result.get('values') and normalized_port(result['values'].get('port')) != normalized_port(expected_port):
        return {'status': 'changed', 'reason': 'The AP port changed during the health read; health withheld'}
    return {**result, 'systemName': name, 'pathVerified': result.get('status') in ('ok', 'partial')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=('reachability', 'switch', 'ap-switch'))
    parser.add_argument('--ip', required=True)
    parser.add_argument('--mac')
    parser.add_argument('--vlan', type=int)
    parser.add_argument('--ifindex', type=int)
    parser.add_argument('--expected-port')
    parser.add_argument('--expected-system')
    args = parser.parse_args()
    if not private_ip(args.ip):
        return {'status': 'invalid', 'reason': 'An RFC1918 IPv4 literal is required'}
    if args.kind == 'reachability':
        return reachability(args.ip)
    if not re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', args.mac or '') or not args.vlan or not 1 <= args.vlan <= 4094 or args.kind == 'switch' and (not args.ifindex or not 1 <= args.ifindex <= 2147483647):
        return {'status': 'invalid', 'reason': 'A verified MAC, VLAN and interface index are required'}
    if args.kind == 'ap-switch':
        if not re.fullmatch(r'(?:te|twe|gi|fa|fo|hu|eth)\d+(?:/\d+){0,3}', normalized_port(args.expected_port)) or not re.fullmatch(r'[A-Za-z0-9._-]{1,253}', args.expected_system or ''):
            return {'status': 'invalid', 'reason': 'A supported AP neighbor port and switch identity are required'}
        return current_ap_port(args.ip, args.mac, args.vlan, args.expected_port, args.expected_system)
    return switch_port(args.ip, args.mac, args.vlan, args.ifindex)


if __name__ == '__main__':
    try:
        print(json.dumps(main()))
    except Exception:
        print(json.dumps({'status': 'unavailable', 'reason': 'The selected-target probe could not complete'}))
