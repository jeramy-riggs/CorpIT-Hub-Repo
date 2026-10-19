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


def lookup_dhcp_lease(device_name, dhcp_server):
    if not valid_hostname(device_name):
        return {"error": "invalid --device: expected a hostname (letters, digits, . _ -; max 64)"}

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
    args = parser.parse_args()

    if not (isinstance(args.server, str) and SERVER_RE.match(args.server)):
        output = {"error": "invalid --server: expected a hostname or IP address"}
    elif args.ip:
        output = lookup_dhcp_by_ip(args.ip, args.server)
    elif args.device:
        output = lookup_dhcp_lease(args.device, args.server)
    else:
        output = {"error": "one of --device or --ip is required"}
    print(json.dumps(output))
