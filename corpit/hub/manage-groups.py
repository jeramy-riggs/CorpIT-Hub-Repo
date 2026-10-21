#!/usr/bin/env python3
"""
manage-groups.py
─────────────────────────────────────────────────────────────────────────────
Add AND/OR remove an AD user from security groups via WinRM / PowerShell.

Input  (stdin):  {
  "samAccountName": "john.doe",
  "addGroups": ["Group1", "Group2"],
  "removeGroups": ["Group3"]
}
Output (stdout): {
  "success": true/false,
  "added": [{ "group": "...", "success": true, "message": "..." }],
  "removed": [{ "group": "...", "success": true, "message": "..." }],
  "error": "..."
}
─────────────────────────────────────────────────────────────────────────────
"""

import sys
import os
import json

try:
    import winrm
except ImportError:
    print(json.dumps({'success': False, 'error': 'pywinrm not installed'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'

# PowerShell's tokenizer treats all of these as single-quote delimiters, not
# just ASCII ' (U+2018, U+2019, U+201A, U+201B). Inside a single-quoted
# literal each one is escaped by doubling it.
_PS_SINGLE_QUOTES = ("'", '\u2018', '\u2019', '\u201a', '\u201b')


def _ps_quote(s):
    """Escape a string for embedding in a single-quoted PowerShell literal."""
    for q in _PS_SINGLE_QUOTES:
        s = s.replace(q, q + q)
    return s


def manage_groups(sam, add_groups, remove_groups, winrm_user, winrm_pass):
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
        return {'success': False, 'error': f'WinRM connection failed: {str(e)}', 'added': [], 'removed': []}

    safe_sam = _ps_quote(sam)

    # Build PowerShell script that processes adds and removes
    add_lines = []
    for g in add_groups:
        add_lines.append(f"    '{_ps_quote(g)}'")

    remove_lines = []
    for g in remove_groups:
        remove_lines.append(f"    '{_ps_quote(g)}'")

    add_array = ",\n".join(add_lines) if add_lines else ""
    remove_array = ",\n".join(remove_lines) if remove_lines else ""

    ps_script = f'''
$addResults = @()
$removeResults = @()
$allSuccess = $true

# ── Add groups ──
$addGroups = @(
{add_array}
)
foreach ($groupName in $addGroups) {{
    if ([string]::IsNullOrWhiteSpace($groupName)) {{ continue }}
    try {{
        Add-ADGroupMember -Identity $groupName -Members '{safe_sam}' -ErrorAction Stop
        $addResults += @{{ group = $groupName; success = $true; message = "Added successfully" }}
    }} catch {{
        $errMsg = $_.Exception.Message
        if ($errMsg -match 'already a member') {{
            $addResults += @{{ group = $groupName; success = $true; message = "Already a member" }}
        }} else {{
            $allSuccess = $false
            $addResults += @{{ group = $groupName; success = $false; message = $errMsg }}
        }}
    }}
}}

# ── Remove groups ──
$removeGroups = @(
{remove_array}
)
foreach ($groupName in $removeGroups) {{
    if ([string]::IsNullOrWhiteSpace($groupName)) {{ continue }}
    try {{
        Remove-ADGroupMember -Identity $groupName -Members '{safe_sam}' -Confirm:$false -ErrorAction Stop
        $removeResults += @{{ group = $groupName; success = $true; message = "Removed successfully" }}
    }} catch {{
        $errMsg = $_.Exception.Message
        if ($errMsg -match 'not a member') {{
            $removeResults += @{{ group = $groupName; success = $true; message = "Was not a member" }}
        }} else {{
            $allSuccess = $false
            $removeResults += @{{ group = $groupName; success = $false; message = $errMsg }}
        }}
    }}
}}

@{{
    success = $allSuccess
    added = $addResults
    removed = $removeResults
}} | ConvertTo-Json -Depth 3
'''

    try:
        result = session.run_ps(ps_script)
        stdout = result.std_out.decode('utf-8', errors='replace').strip()
        stderr = result.std_err.decode('utf-8', errors='replace').strip()

        if result.status_code != 0 and not stdout:
            return {'success': False, 'error': f'PowerShell error: {stderr}', 'added': [], 'removed': []}

        try:
            parsed = json.loads(stdout)
            # PowerShell wraps single results differently
            if 'added' in parsed and not isinstance(parsed['added'], list):
                parsed['added'] = [parsed['added']] if parsed['added'] else []
            if 'removed' in parsed and not isinstance(parsed['removed'], list):
                parsed['removed'] = [parsed['removed']] if parsed['removed'] else []
            return parsed
        except json.JSONDecodeError:
            return {'success': False, 'error': f'Unexpected output: {stdout}', 'added': [], 'removed': []}

    except winrm.exceptions.InvalidCredentialsError:
        return {'success': False, 'error': 'WinRM authentication failed', 'added': [], 'removed': []}
    except winrm.exceptions.WinRMTransportError as e:
        return {'success': False, 'error': f'WinRM transport error: {str(e)}', 'added': [], 'removed': []}
    except Exception as e:
        return {'success': False, 'error': f'Unexpected error: {str(e)}', 'added': [], 'removed': []}


if __name__ == '__main__':
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
    except Exception as e:
        print(json.dumps({'success': False, 'error': f'Invalid input: {str(e)}'}))
        sys.exit(1)

    sam = payload.get('samAccountName', '').strip()
    add_groups = payload.get('addGroups', [])
    remove_groups = payload.get('removeGroups', [])

    if not sam:
        print(json.dumps({'success': False, 'error': 'samAccountName is required'}))
        sys.exit(1)

    if not add_groups and not remove_groups:
        print(json.dumps({'success': False, 'error': 'No groups to add or remove'}))
        sys.exit(1)

    winrm_user = os.environ.get('WINRM_USER', '')
    winrm_pass = os.environ.get('WINRM_PASS', '')

    if not winrm_user or not winrm_pass:
        print(json.dumps({'success': False, 'error': 'WINRM_USER and WINRM_PASS not set'}))
        sys.exit(1)

    result = manage_groups(sam, add_groups, remove_groups, winrm_user, winrm_pass)
    print(json.dumps(result))
