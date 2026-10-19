#!/usr/bin/env python3
"""
gpo-report.py
─────────────────────────────────────────────────────────────────────────────
Pull a full `Get-GPOReport -All -ReportType Xml` from the DC over WinRM.

Mirrors gpo-actions.py's connection exactly (pywinrm / NTLM to the DC,
credentials from WINRM_USER / WINRM_PASS). READ-ONLY against AD — it only
reads Group Policy, it never changes anything.

Output:
  success  → raw XML written to stdout, exit 0
  failure  → JSON {"error": "...", "errorCode": "..."} to stdout, exit 1
─────────────────────────────────────────────────────────────────────────────
"""

import sys
import os
import json

try:
    import winrm
except ImportError:
    print(json.dumps({'error': 'pywinrm not installed', 'errorCode': 'winrm_error'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'  # same DC as gpo-actions.py

# All GPOs: write with -Path (single well-formed doc, same format as manual
# uploads), then read it back. Streaming -All to stdout yields multiple XML
# roots which the parser rejects. -Server pins the local DC (avoids 0x80072020).
PS_SCRIPT_ALL = r"""
$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy -ErrorAction Stop
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("gpoall_" + [guid]::NewGuid().ToString() + ".xml")
Get-GPOReport -All -ReportType Xml -Server $env:COMPUTERNAME -Path $tmp
[System.IO.File]::ReadAllText($tmp)
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
"""

# Single GPO by GUID -> one well-formed <GPO> document straight to stdout.
def build_single_script(guid):
    safe = guid.replace("'", "''")
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "Import-Module GroupPolicy -ErrorAction Stop\n"
        f"Get-GPOReport -Guid '{safe}' -ReportType Xml -Server $env:COMPUTERNAME\n"
    )


def main():
    winrm_user = os.environ.get('WINRM_USER', '')
    winrm_pass = os.environ.get('WINRM_PASS', '')
    if not winrm_user or not winrm_pass:
        print(json.dumps({'error': 'WINRM_USER / WINRM_PASS not set', 'errorCode': 'invalid_input'}))
        sys.exit(1)

    try:
        session = winrm.Session(
            f'http://{DC_HOST}:5985/wsman',
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=120,
            read_timeout_sec=130,
        )
    except Exception as e:
        print(json.dumps({'error': f'WinRM connection failed: {e}', 'errorCode': 'winrm_error'}))
        sys.exit(1)

    guid = os.environ.get('GPO_GUID', '').strip().lower().replace('{', '').replace('}', '')
    ps_script = build_single_script(guid) if guid else PS_SCRIPT_ALL

    try:
        result = session.run_ps(ps_script)
    except Exception as e:
        print(json.dumps({'error': f'WinRM run failed: {e}', 'errorCode': 'winrm_error'}))
        sys.exit(1)

    stdout = result.std_out.decode('utf-8', errors='replace')
    stderr = result.std_err.decode('utf-8', errors='replace')

    if result.status_code != 0 or not stdout.lstrip('﻿ \t\r\n').startswith('<'):
        msg = (stderr or stdout or 'Get-GPOReport failed').strip()[:2000]
        print(json.dumps({'error': msg, 'errorCode': 'powershell_error'}))
        sys.exit(1)

    sys.stdout.write(stdout)
    sys.exit(0)


if __name__ == '__main__':
    main()
