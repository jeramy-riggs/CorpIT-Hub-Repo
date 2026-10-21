#!/usr/bin/env python3
"""
gpo-actions.py
─────────────────────────────────────────────────────────────────────────────
Apply GPO remediation actions via WinRM / PowerShell.

Mirrors the manage-groups.py pattern exactly:
  - Pywinrm over NTLM to the DC
  - Reads JSON from stdin, writes JSON to stdout
  - WinRM credentials from WINRM_USER / WINRM_PASS env vars
  - Single-quote escape via doubling for PowerShell safety
  - Errors surfaced as structured JSON with errorCode for the UI

Phase 2 v1 supports ONE action type:
  remove_gpo  →  Backup-GPO  →  Remove-GPO -Confirm:$false

Always backs up before destructive operations. PowerShell try/catch wraps
both steps; if the backup fails the remove never runs.

Input  (stdin):  {
  "actionType":  "remove_gpo",
  "gpoName":     "Some GPO Name",
  "gpoGuid":     "{xxxxxxxx-xxxx-...}",
  "backupPath":  "C:\\GPOBackups"          (optional, default below)
}

Output (stdout): {
  "success":         true | false,
  "actionType":      "remove_gpo",
  "gpoName":         "...",
  "gpoGuid":         "...",
  "backupId":        "<guid>" | null,       # only on success
  "backupTimestamp": "ISO-8601" | null,
  "exitCode":        0 | non-zero,
  "stdout":          "<powershell output>",
  "stderr":          "<powershell error stream>",
  "error":           "..." | null,
  "errorCode":       null
                     | "permission_denied"   (Access denied, InsufficientRights)
                     | "gpo_not_found"       (Cannot find GPO with name)
                     | "backup_path_invalid" (target path doesn't exist)
                     | "winrm_error"         (cannot reach DC)
                     | "powershell_error"    (anything else from PS)
                     | "invalid_input"       (bad stdin payload)
}
─────────────────────────────────────────────────────────────────────────────
"""

import sys
import os
import json
import re

try:
    import winrm
except ImportError:
    print(json.dumps({'success': False, 'error': 'pywinrm not installed', 'errorCode': 'winrm_error'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'
DEFAULT_BACKUP_PATH = 'C:\\GPOBackups'
ALLOWED_ACTIONS = {'remove_gpo'}  # v1 — extended in v2


# PowerShell's tokenizer treats all of these as single-quote delimiters, not
# just ASCII ' (U+2018, U+2019, U+201A, U+201B). Inside a single-quoted
# literal each one is escaped by doubling it.
_PS_SINGLE_QUOTES = ("'", '\u2018', '\u2019', '\u201a', '\u201b')


def _ps_quote(s):
    """Escape a string for embedding in a single-quoted PowerShell literal."""
    for q in _PS_SINGLE_QUOTES:
        s = s.replace(q, q + q)
    return s


def _classify_error(stdout, stderr, status_code):
    """Map PowerShell error text to a structured errorCode the UI can branch on."""
    blob = (stdout or '') + '\n' + (stderr or '')
    low = blob.lower()
    if re.search(r'access (?:is )?denied|insufficient ?rights|requires elevation', low):
        return 'permission_denied'
    if re.search(r'cannot find (?:the )?gpo|cannot find an? object with identity', low):
        return 'gpo_not_found'
    if re.search(r'cannot find path|backuppath.*not exist|directory.*does not exist', low):
        return 'backup_path_invalid'
    if status_code != 0 or 'exception' in low or 'error' in low:
        return 'powershell_error'
    return None


def _build_remove_gpo_script(gpo_name, gpo_guid, backup_path):
    """
    PowerShell that backs up then removes a GPO. Both steps are wrapped in a
    single try/catch so a backup failure aborts the remove.

    Outputs a JSON object on stdout describing success/failure with backup info.
    """
    safe_name = _ps_quote(gpo_name)
    safe_guid = _ps_quote(gpo_guid or '')
    safe_path = _ps_quote(backup_path)
    return f"""$ErrorActionPreference = 'Stop'
try {{
    if (-not (Test-Path -LiteralPath '{safe_path}')) {{
        New-Item -ItemType Directory -Path '{safe_path}' -Force | Out-Null
    }}
    $backup = Backup-GPO -Name '{safe_name}' -Path '{safe_path}' -Comment "IT Command apply tool — pre-remove backup $(Get-Date -Format yyyy-MM-dd-HHmmss)"
    Remove-GPO -Name '{safe_name}' -Confirm:$false
    @{{
        success         = $true
        action          = 'remove_gpo'
        gpoName         = '{safe_name}'
        gpoGuid         = '{safe_guid}'
        backupId        = $backup.Id.ToString()
        backupTimestamp = $backup.Timestamp.ToString('o')
        backupPath      = '{safe_path}'
    }} | ConvertTo-Json -Depth 3 -Compress
}} catch {{
    @{{
        success      = $false
        action       = 'remove_gpo'
        gpoName      = '{safe_name}'
        gpoGuid      = '{safe_guid}'
        errorMessage = $_.Exception.Message
        errorType    = $_.Exception.GetType().FullName
    }} | ConvertTo-Json -Depth 3 -Compress
    exit 1
}}
"""


def execute(payload, winrm_user, winrm_pass):
    action_type = payload.get('actionType', '')
    if action_type not in ALLOWED_ACTIONS:
        return {
            'success': False,
            'error': f'Unsupported action type: {action_type!r}. v1 supports: {sorted(ALLOWED_ACTIONS)}',
            'errorCode': 'invalid_input',
        }

    gpo_name = (payload.get('gpoName') or '').strip()
    gpo_guid = (payload.get('gpoGuid') or '').strip()
    backup_path = (payload.get('backupPath') or DEFAULT_BACKUP_PATH).strip()

    if not gpo_name:
        return {'success': False, 'error': 'gpoName required', 'errorCode': 'invalid_input'}

    # Open WinRM session
    try:
        session = winrm.Session(
            f'http://{DC_HOST}:5985/wsman',
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=60,
            read_timeout_sec=70,
        )
    except Exception as e:
        return {
            'success': False, 'actionType': action_type, 'gpoName': gpo_name, 'gpoGuid': gpo_guid,
            'error': f'WinRM connection failed: {e}', 'errorCode': 'winrm_error',
            'stdout': '', 'stderr': '', 'exitCode': -1,
        }

    ps_script = _build_remove_gpo_script(gpo_name, gpo_guid, backup_path)

    try:
        result = session.run_ps(ps_script)
    except winrm.exceptions.InvalidCredentialsError:
        return {
            'success': False, 'actionType': action_type, 'gpoName': gpo_name, 'gpoGuid': gpo_guid,
            'error': 'WinRM authentication failed', 'errorCode': 'permission_denied',
            'stdout': '', 'stderr': '', 'exitCode': -1,
        }
    except winrm.exceptions.WinRMTransportError as e:
        return {
            'success': False, 'actionType': action_type, 'gpoName': gpo_name, 'gpoGuid': gpo_guid,
            'error': f'WinRM transport error: {e}', 'errorCode': 'winrm_error',
            'stdout': '', 'stderr': '', 'exitCode': -1,
        }
    except Exception as e:
        return {
            'success': False, 'actionType': action_type, 'gpoName': gpo_name, 'gpoGuid': gpo_guid,
            'error': f'Unexpected error: {e}', 'errorCode': 'powershell_error',
            'stdout': '', 'stderr': '', 'exitCode': -1,
        }

    stdout = result.std_out.decode('utf-8', errors='replace').strip()
    stderr = result.std_err.decode('utf-8', errors='replace').strip()
    status_code = result.status_code

    out = {
        'success':         False,
        'actionType':      action_type,
        'gpoName':         gpo_name,
        'gpoGuid':         gpo_guid,
        'backupId':        None,
        'backupTimestamp': None,
        'exitCode':        status_code,
        'stdout':          stdout,
        'stderr':          stderr,
        'error':           None,
        'errorCode':       None,
    }

    # Try to parse the JSON the PowerShell emitted. Whether success=true or
    # success=false, our PS always emits ConvertTo-Json on the relevant path.
    parsed = None
    if stdout:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = None

    if parsed and isinstance(parsed, dict):
        if parsed.get('success') is True and status_code == 0:
            out['success'] = True
            out['backupId'] = parsed.get('backupId')
            out['backupTimestamp'] = parsed.get('backupTimestamp')
            return out
        # Failure: capture error details from PS
        out['error'] = parsed.get('errorMessage') or parsed.get('error') or 'PowerShell reported failure'
        out['errorCode'] = _classify_error(stdout, stderr, status_code) or 'powershell_error'
        return out

    # Non-JSON output path: classify from raw streams
    out['error'] = stderr or stdout or 'Unknown PowerShell failure'
    out['errorCode'] = _classify_error(stdout, stderr, status_code) or 'powershell_error'
    return out


# ── Entry point ──────────────────────────────────────────────────────
if __name__ == '__main__':
    try:
        payload = json.loads(sys.stdin.read())
    except Exception as e:
        print(json.dumps({'success': False, 'error': f'Invalid input: {e}', 'errorCode': 'invalid_input'}))
        sys.exit(1)

    winrm_user = os.environ.get('WINRM_USER', '')
    winrm_pass = os.environ.get('WINRM_PASS', '')
    if not winrm_user or not winrm_pass:
        print(json.dumps({'success': False, 'error': 'WINRM_USER / WINRM_PASS not set', 'errorCode': 'invalid_input'}))
        sys.exit(1)

    result = execute(payload, winrm_user, winrm_pass)
    print(json.dumps(result))
    sys.exit(0 if result.get('success') else 1)
