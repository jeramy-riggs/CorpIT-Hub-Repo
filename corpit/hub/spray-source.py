#!/usr/bin/env python3
"""
Spray Source Finder - queries DC Security Event Log via WinRM for
Event 4625 (failed logon) tenant-wide, no username filter.
Returns JSON list of {time, user, ip, workstation} for spray bucketing.

Usage: python3 spray-source.py [lookback_minutes]
Reads WINRM_USER and WINRM_PASS from environment variables.
Mirrors lockout-source.py connection pattern.
"""
import sys
import os
import json

try:
    import winrm
except ImportError:
    print(json.dumps({'error': 'pywinrm not installed - run: pip install pywinrm --break-system-packages'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'


def get_failed_logons(minutes, winrm_user, winrm_pass):
    try:
        session = winrm.Session(
            f'http://{DC_HOST}:5985/wsman',
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=45,
            read_timeout_sec=50,
        )
        # 4625 EventData carries TargetUserName and IpAddress fields directly,
        # so we read them from XML rather than regex the message string.
        ps_script = f'''
$start = (Get-Date).AddMinutes(-{minutes})
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security'
    Id=4625
    StartTime=$start
}} -MaxEvents 2000 -ErrorAction SilentlyContinue
$results = @()
foreach ($event in $events) {{
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data
    $targetUser = ($data | Where-Object {{ $_.Name -eq 'TargetUserName' }}).'#text'
    $ip         = ($data | Where-Object {{ $_.Name -eq 'IpAddress' }}).'#text'
    $ws         = ($data | Where-Object {{ $_.Name -eq 'WorkstationName' }}).'#text'
    if ([string]::IsNullOrEmpty($targetUser)) {{ continue }}
    # Skip machine accounts and system noise
    if ($targetUser -match '\\$$' -or $targetUser -eq '-') {{ continue }}
    $results += @{{
        time = $event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
        user = $targetUser
        ip   = $ip
        workstation = $ws
    }}
}}
$results | ConvertTo-Json -Compress -Depth 3
if ($results.Count -eq 0) {{ '[]' }}
'''
        result = session.run_ps(ps_script)
        if result.status_code != 0:
            return {'error': 'WinRM script failed', 'detail': result.std_err.decode('utf-8', 'ignore')[:500]}
        out = result.std_out.decode('utf-8', 'ignore').strip()
        if not out:
            return []
        # ConvertTo-Json emits a bare object (not array) for a single item
        parsed = json.loads(out)
        if isinstance(parsed, dict):
            parsed = [parsed]
        return parsed
    except Exception as e:
        return {'error': str(e)}


def main():
    minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    winrm_user = os.environ.get('WINRM_USER')
    winrm_pass = os.environ.get('WINRM_PASS')
    if not winrm_user or not winrm_pass:
        print(json.dumps({'error': 'WINRM_USER / WINRM_PASS not set in environment'}))
        sys.exit(1)
    print(json.dumps(get_failed_logons(minutes, winrm_user, winrm_pass)))


if __name__ == '__main__':
    main()
