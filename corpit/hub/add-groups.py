#!/usr/bin/env python3
"""
add-groups.py
─────────────────────────────────────────────────────────────────────────────
Add an AD user to one or more security groups via WinRM / PowerShell.

Input  (stdin):  { "samAccountName": "john.doe", "groups": ["Group1", "Group2"] }
Output (stdout): { "success": true/false, "results": [...], "error": "..." }

Environment variables required:
  WINRM_USER  — domain\\user with permission to modify group memberships
  WINRM_PASS  — password for the WinRM account
─────────────────────────────────────────────────────────────────────────────
"""

import sys
import os
import json

try:
    import winrm
except ImportError:
    print(json.dumps({'success': False, 'error': 'pywinrm not installed on server'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'


def add_user_to_groups(sam, groups, winrm_user, winrm_pass):
    """Connect to DC via WinRM and run Add-ADGroupMember for each group."""
    try:
        session = winrm.Session(
            f'http://{DC_HOST}:5985/wsman',
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=30,
            read_timeout_sec=35,
        )
    except Exception as e:
        return {'success': False, 'error': f'WinRM connection failed: {str(e)}', 'results': []}

    # Escape the username for PowerShell
    safe_sam = sam.replace("'", "''")

    # Build a PowerShell script that processes each group individually
    # and returns per-group success/failure
    group_lines = []
    for g in groups:
        safe_g = g.replace("'", "''")
        group_lines.append(f"    '{safe_g}'")

    groups_array = ",\n".join(group_lines)

    ps_script = f'''
$results = @()
$groups = @(
{groups_array}
)

$allSuccess = $true
foreach ($groupName in $groups) {{
    try {{
        Add-ADGroupMember -Identity $groupName -Members '{safe_sam}' -ErrorAction Stop
        $results += @{{
            group   = $groupName
            success = $true
            message = "Added successfully"
        }}
    }} catch {{
        $errMsg = $_.Exception.Message
        # Check if user is already a member (not a real failure)
        if ($errMsg -match 'already a member') {{
            $results += @{{
                group   = $groupName
                success = $true
                message = "Already a member"
            }}
        }} else {{
            $allSuccess = $false
            $results += @{{
                group   = $groupName
                success = $false
                message = $errMsg
            }}
        }}
    }}
}}

@{{
    success = $allSuccess
    results = $results
}} | ConvertTo-Json -Depth 3
'''

    try:
        result = session.run_ps(ps_script)
        stdout = result.std_out.decode('utf-8', errors='replace').strip()
        stderr = result.std_err.decode('utf-8', errors='replace').strip()

        if result.status_code != 0 and not stdout:
            return {'success': False, 'error': f'PowerShell error: {stderr}', 'results': []}

        try:
            parsed = json.loads(stdout)
            # PowerShell sometimes wraps single results differently
            if 'results' in parsed and not isinstance(parsed['results'], list):
                parsed['results'] = [parsed['results']]
            return parsed
        except json.JSONDecodeError:
            return {'success': False, 'error': f'Unexpected output: {stdout}', 'results': []}

    except winrm.exceptions.InvalidCredentialsError:
        return {'success': False, 'error': 'WinRM authentication failed', 'results': []}
    except winrm.exceptions.WinRMTransportError as e:
        return {'success': False, 'error': f'WinRM transport error: {str(e)}', 'results': []}
    except Exception as e:
        return {'success': False, 'error': f'Unexpected error: {str(e)}', 'results': []}


if __name__ == '__main__':
    # Read JSON payload from stdin
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
    except (json.JSONDecodeError, Exception) as e:
        print(json.dumps({'success': False, 'error': f'Invalid input: {str(e)}'}))
        sys.exit(1)

    sam = payload.get('samAccountName', '').strip()
    groups = payload.get('groups', [])

    if not sam:
        print(json.dumps({'success': False, 'error': 'samAccountName is required'}))
        sys.exit(1)

    if not groups or not isinstance(groups, list):
        print(json.dumps({'success': False, 'error': 'groups must be a non-empty list'}))
        sys.exit(1)

    winrm_user = os.environ.get('WINRM_USER', '')
    winrm_pass = os.environ.get('WINRM_PASS', '')

    if not winrm_user or not winrm_pass:
        print(json.dumps({'success': False, 'error': 'WINRM_USER and WINRM_PASS not set'}))
        sys.exit(1)

    result = add_user_to_groups(sam, groups, winrm_user, winrm_pass)
    print(json.dumps(result))
