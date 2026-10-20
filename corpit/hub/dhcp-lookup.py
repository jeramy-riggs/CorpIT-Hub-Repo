#!/usr/bin/env python3
"""
dhcp-lookup.py
Queries a Windows DHCP server via WinRM to find the current active IP lease
for a given device name.

Called by fortinet-lookup.js via child_process.execFile
Usage:
  python3 dhcp-lookup.py --device "NRPI-LAP-1234" --server "10.20.10.52"

Returns JSON on stdout:
  Success: {"ip":"10.20.23.45","hostname":"NRPI-LAP-1234","mac":"aa:bb:cc:dd:ee:ff","scope":"10.20.23.0","state":"Active"}
  Failure: {"error":"reason string"}
"""

import winrm
import json
import sys
import argparse
import os
import ipaddress
import re
import socket

# Input validation (CR-2). --device and --ip are interpolated into a PowerShell
# script that runs on the DHCP server, so only a strict whitelist may pass.
# The JS callers (netdiag.js, fortinet-lookup.js) validate too; this is the
# last line of defence and runs BEFORE any PowerShell text is built.
HOSTNAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
SERVER_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')


def valid_hostname(value):
    return isinstance(value, str) and HOSTNAME_RE.match(value) is not None


def valid_ipv4(value):
    """Return the normalised IPv4 literal, or None if value is not one."""
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    # Get-DhcpServerv4Lease only; also rules out IPv6 scope-id suffixes.
    if addr.version != 4:
        return None
    return str(addr)


def broker_lookup(mode, query, server):
    """Use DEV's constrained reader when configured; fail closed on IPC failure."""
    path = os.environ.get('DHCP_LOOKUP_SOCKET')
    if not path:
        return None
    exact = mode.startswith('exact_')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(21)
            connection.connect(path)
            connection.sendall(json.dumps({'mode': mode, 'query': query, 'server': server}).encode() + b'\n')
            data = bytearray()
            while b'\n' not in data:
                block = connection.recv(65536)
                if not block:
                    raise ValueError('Incomplete response')
                data.extend(block)
                if len(data) > 1024 * 1024:
                    raise ValueError('Response too large')
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ValueError('Invalid response')
            if exact and (result.get('status') not in ('ok', 'unavailable') or not isinstance(result.get('leases'), list)):
                raise ValueError('Invalid exact response')
            if not exact and not ('error' in result or 'ip' in result):
                raise ValueError('Invalid legacy response')
            return result
    except Exception:
        result = {'code': 'DHCP_BROKER_UNAVAILABLE', 'error': 'DHCP read service is unavailable'}
        if exact:
            result.update(status='unavailable', leases=[])
        return result


def lookup_dhcp_lease(device_name, dhcp_server):
    if not valid_hostname(device_name):
        return {"error": "invalid --device: expected a hostname (letters, digits, . _ -; max 64)"}

    broker = broker_lookup('hostname', device_name, dhcp_server)
    if broker is not None:
        return broker

    winrm_user = os.environ.get('WINRM_USER')
    winrm_pass = os.environ.get('WINRM_PASS')

    if not winrm_user or not winrm_pass:
        return {"error": "WinRM credentials not configured in environment"}

    # PowerShell: search all DHCP scopes on the server for a hostname
    # containing the device name (partial match handles FQDN suffixes).
    # Runs locally on the DHCP server itself (ComputerName localhost)
    # because WinRM already connects us to that machine.
    ps_command = f"""
$ErrorActionPreference = 'Stop'
try {{
    $scopes = Get-DhcpServerv4Scope -ComputerName localhost
    $found = $null
    foreach ($scope in $scopes) {{
        $leases = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId `
                    -ComputerName localhost -ErrorAction SilentlyContinue
        $match = $leases | Where-Object {{
            $_.HostName -like '*{device_name}*' -and
            $_.AddressState -like '*Active*'
        }} | Sort-Object LeaseExpiryTime -Descending | Select-Object -First 1
        if ($match) {{
            $found = [ordered]@{{
                ip       = $match.IPAddress.ToString()
                hostname = $match.HostName
                mac      = $match.ClientId
                scope    = $scope.ScopeId.ToString()
                state    = $match.AddressState.ToString()
            }}
            break
        }}
    }}
    if ($found) {{
        $found | ConvertTo-Json -Compress
    }} else {{
        Write-Output '{{"error":"No active DHCP lease found for device: {device_name}"}}'
    }}
}} catch {{
    $msg = $_.Exception.Message -replace '"', "'"
    Write-Output "{{\\"error\\":\\"$msg\\"}}"
}}
"""

    try:
        session = winrm.Session(
            dhcp_server,
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=30,
            read_timeout_sec=35
        )

        result = session.run_ps(ps_command)

        if result.status_code != 0:
            stderr = result.std_err.decode('utf-8', errors='replace').strip()
            # Strip XML WinRM error wrapping for cleaner message
            if '<f:Message>' in stderr:
                import re
                match = re.search(r'<f:Message>(.*?)</f:Message>', stderr, re.DOTALL)
                if match:
                    stderr = match.group(1).strip()
            return {"error": f"PowerShell error: {stderr}"}

        output = result.std_out.decode('utf-8', errors='replace').strip()

        if not output:
            return {"error": "DHCP server returned no output"}

        return json.loads(output)

    except json.JSONDecodeError:
        return {"error": "Failed to parse DHCP server response", "raw": output[:500]}
    except Exception as e:
        return {"error": f"WinRM connection failed: {str(e)}"}


def lookup_dhcp_by_ip(ip_address, dhcp_server):
    ip_address = valid_ipv4(ip_address)
    if ip_address is None:
        return {"error": "invalid --ip: expected an IPv4 address"}

    broker = broker_lookup('ip', ip_address, dhcp_server)
    if broker is not None:
        return broker

    winrm_user = os.environ.get('WINRM_USER')
    winrm_pass = os.environ.get('WINRM_PASS')
    if not winrm_user or not winrm_pass:
        return {"error": "WinRM credentials not configured in environment"}
    ps_command = f"""
$ErrorActionPreference = 'Stop'
try {{
    $scopes = Get-DhcpServerv4Scope -ComputerName localhost
    $found = $null
    foreach ($scope in $scopes) {{
        $lease = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId `
                    -ComputerName localhost -ErrorAction SilentlyContinue |
                 Where-Object {{ $_.IPAddress.ToString() -eq '{ip_address}' }} |
                 Sort-Object LeaseExpiryTime -Descending | Select-Object -First 1
        if ($lease) {{
            $found = [ordered]@{{
                ip       = $lease.IPAddress.ToString()
                hostname = $lease.HostName
                mac      = $lease.ClientId
                scope    = $scope.ScopeId.ToString()
                state    = $lease.AddressState.ToString()
            }}
            break
        }}
    }}
    if ($found) {{
        $found | ConvertTo-Json -Compress
    }} else {{
        Write-Output '{{"error":"No active DHCP lease found for IP: {ip_address}"}}'
    }}
}} catch {{
    $msg = $_.Exception.Message -replace '"', "'"
    Write-Output "{{\"error\":\"$msg\"}}"
}}
"""
    try:
        session = winrm.Session(
            dhcp_server,
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=30,
            read_timeout_sec=35
        )
        result = session.run_ps(ps_command)
        if result.status_code != 0:
            stderr = result.std_err.decode('utf-8', errors='replace').strip()
            if '<f:Message>' in stderr:
                import re
                m = re.search(r'<f:Message>(.*?)</f:Message>', stderr, re.DOTALL)
                if m:
                    stderr = m.group(1).strip()
            return {"error": f"PowerShell error: {stderr}"}
        output = result.std_out.decode('utf-8', errors='replace').strip()
        if not output:
            return {"error": "DHCP server returned no output"}
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": "Failed to parse DHCP server response", "raw": output[:500]}
    except Exception as e:
        return {"error": f"WinRM connection failed: {str(e)}"}


def exact_query(device=None, mac=None):
    """Build a read-only query returning every exact active match, never a first match."""
    if bool(device) == bool(mac):
        raise ValueError('Choose exactly one hostname or MAC')
    if device and not valid_hostname(device):
        raise ValueError('Invalid exact hostname')
    if mac and not re.fullmatch(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}', mac):
        raise ValueError('Invalid exact MAC')
    # A short inventory name may match the short portion of a lease FQDN.
    # A supplied FQDN must match in full; suffix variants remain separate results.
    wanted = device.lower().rstrip('.') if device else mac.replace(':', '').lower()
    predicate = ("$name -eq '" + wanted + "'" if device and '.' in wanted else
                 "($name -split '\\.')[0] -eq '" + wanted + "'" if device else
                 "($_.ClientId -replace '[:-]', '').ToLowerInvariant() -eq '" + wanted + "'")
    return """
$ErrorActionPreference = 'Stop'
try {
  $leaseMatches = @()
  foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName localhost -ErrorAction Stop)) {
    foreach ($lease in @(Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ComputerName localhost -ErrorAction Stop)) {
      $ok = $lease | Where-Object {
        $name = ([string]$_.HostName).TrimEnd('.').ToLowerInvariant()
        ($_.AddressState.ToString() -eq 'Active' -or $_.AddressState.ToString() -eq 'ActiveReservation') -and (PREDICATE)
      }
      if ($ok) {
        $leaseMatches += [ordered]@{ip=$lease.IPAddress.ToString();hostname=$lease.HostName;mac=$lease.ClientId;scope=$scope.ScopeId.ToString();state=$lease.AddressState.ToString();expiresAt=$lease.LeaseExpiryTime.ToUniversalTime().ToString('o')}
      }
    }
  }
  @{status='ok';leases=@($leaseMatches)} | ConvertTo-Json -Depth 4 -Compress
} catch { @{status='unavailable';leases=@();code='DHCP_QUERY_FAILED';error='Exact DHCP query failed'} | ConvertTo-Json -Compress }
""".replace('PREDICATE', predicate)


def lookup_dhcp_exact(device, mac, server):
    try:
        command = exact_query(device, mac)
    except ValueError as error:
        return {'status': 'invalid', 'leases': [], 'error': str(error)}
    broker = broker_lookup('exact_hostname' if device else 'exact_mac', device or mac, server)
    if broker is not None:
        return broker
    if not os.environ.get('WINRM_USER') or not os.environ.get('WINRM_PASS'):
        return {'status': 'unavailable', 'leases': [], 'code': 'WINRM_UNCONFIGURED', 'error': 'WinRM credentials are not configured'}
    try:
        session = winrm.Session(server, auth=(os.environ['WINRM_USER'], os.environ['WINRM_PASS']),
                                transport='ntlm', server_cert_validation='ignore', operation_timeout_sec=30, read_timeout_sec=35)
        result = session.run_ps(command)
        if result.status_code != 0:
            return {'status': 'unavailable', 'leases': [], 'code': 'DHCP_POWERSHELL_FAILED', 'error': 'The remote DHCP command could not run'}
        value = json.loads(result.std_out.decode('utf-8').strip())
        if value.get('status') not in ('ok', 'unavailable') or not isinstance(value.get('leases'), list):
            raise ValueError('Invalid DHCP response')
        return value
    except Exception as error:
        return {'status': 'unavailable', 'leases': [], 'code': 'WINRM_' + type(error).__name__, 'error': 'Exact DHCP query could not be completed'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Query a Windows DHCP server for a device IP lease via WinRM'
    )
    parser.add_argument('--device', required=False,
                        help='Device name (or partial name) to search for')
    parser.add_argument('--ip', required=False,
                        help='IP address to reverse-lookup to a device/hostname')
    parser.add_argument('--server', required=True,
                        help='DHCP server IP address to connect to via WinRM')
    parser.add_argument('--exact', action='store_true', help='Return all exact active matches')
    parser.add_argument('--mac', required=False, help='Exact MAC in --exact mode')
    args = parser.parse_args()

    if not (isinstance(args.server, str) and SERVER_RE.match(args.server)):
        output = {"error": "invalid --server: expected a hostname or IP address"}
    elif args.exact:
        output = lookup_dhcp_exact(args.device, args.mac, args.server)
    elif args.ip:
        output = lookup_dhcp_by_ip(args.ip, args.server)
    elif args.device:
        output = lookup_dhcp_lease(args.device, args.server)
    else:
        output = {"error": "one of --device or --ip is required"}
    print(json.dumps(output))
