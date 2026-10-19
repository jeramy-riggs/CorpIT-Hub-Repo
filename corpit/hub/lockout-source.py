#!/usr/bin/env python3
"""
Lockout Source Finder — queries DC Security Event Log via WinRM
Usage: python3 lockout-source.py <username>   (or TARGET_USER=<username> in the environment)
Reads WINRM_USER and WINRM_PASS from environment variables
"""
import sys
import os
import re
import json

try:
    import winrm
except ImportError:
    print(json.dumps({'error': 'pywinrm not installed — run: pip install pywinrm --break-system-packages'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'

# CR-1: sAMAccountName / UPN shape only. Mirrors LOCKOUT_IDENTITY_RE in
# identity-routes.js so the helper is safe even when invoked by hand.
USERNAME_RE = re.compile(r'[A-Za-z0-9._@\-]{1,64}')

def get_lockout_events(username, winrm_user, winrm_pass):
    try:
        session = winrm.Session(
            f'http://{DC_HOST}:5985/wsman',
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=30,
            read_timeout_sec=35,
        )

        # CR-1: never splice the raw value into the script. Single-quoted
        # PowerShell literal with ' doubled (same as password-reset.py), then
        # [regex]::Escape so it is matched literally, not as a pattern.
        safe_user = username.replace("'", "''")

        ps_script = f'''
$u = [regex]::Escape('{safe_user}')
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security'
    Id=4740
}} -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {{
    $_.Message -match $u
}} | Select-Object -First 10

$results = @()
foreach ($event in $events) {{
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data
    $targetUser = ($data | Where-Object {{ $_.Name -eq 'TargetUserName' }}).'#text'
    $source = ''
    $msg = $event.Message
    if ($msg -match 'Caller Computer Name:\\s*(\\S+)') {{
        $source = $Matches[1]
    }}

    $results += @{{
        TimeCreated = $event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
        TargetUser = $targetUser
        CallerComputer = $source
        DC = $event.MachineName
        Message = ($msg -split "`n" | Select-Object -First 5) -join " | "
    }}
}}

if ($results.Count -eq 0) {{
    '[]'
}} else {{
    $results | ConvertTo-Json -Depth 3
}}
'''
        result = session.run_ps(ps_script)

        if result.status_code != 0:
            error_msg = result.std_err.decode('utf-8', errors='replace').strip()
            return {'error': f'PowerShell error: {error_msg}', 'events': []}

        stdout = result.std_out.decode('utf-8', errors='replace').strip()

        if not stdout or stdout == '' or stdout == '[]':
            return {'events': [], 'message': f'No lockout events found for {username}'}

        try:
            events = json.loads(stdout)
            if isinstance(events, dict):
                events = [events]
            return {'events': events}
        except json.JSONDecodeError:
            return {'events': [], 'raw': stdout}

    except winrm.exceptions.InvalidCredentialsError:
        return {'error': 'WinRM authentication failed — check WINRM_USER and WINRM_PASS in .env'}
    except winrm.exceptions.WinRMTransportError as e:
        return {'error': f'WinRM connection failed: {str(e)}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


if __name__ == '__main__':
    # Preferred: TARGET_USER in the environment (set by identity-routes.js).
    # argv is kept for manual CLI use. Both go through the same whitelist.
    username = (os.environ.get('TARGET_USER') or (sys.argv[1] if len(sys.argv) > 1 else '')).strip()
    if not username:
        print(json.dumps({'error': 'Usage: lockout-source.py <username>  (or TARGET_USER=<username>)'}))
        sys.exit(1)
    if not USERNAME_RE.fullmatch(username):
        print(json.dumps({'error': 'Invalid username: only letters, digits, . _ @ - (max 64 chars) are allowed'}))
        sys.exit(1)

    winrm_user = os.environ.get('WINRM_USER', '')
    winrm_pass = os.environ.get('WINRM_PASS', '')

    if not winrm_user or not winrm_pass:
        print(json.dumps({'error': 'WINRM_USER and WINRM_PASS not set in environment'}))
        sys.exit(1)

    result = get_lockout_events(username, winrm_user, winrm_pass)
    print(json.dumps(result))
