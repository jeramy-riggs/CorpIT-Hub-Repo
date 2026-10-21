#!/usr/bin/env python3
"""
housekeeping-actions.py
─────────────────────────────────────────────────────────────────────────────
Executes AD housekeeping actions via WinRM/PowerShell.

Input (stdin): JSON with "action" + params
Output (stdout): JSON result

Actions:
  disable-account     { target: "samAccountName" }
  enable-account      { target: "samAccountName" }
  move-to-disabled    { target: "samAccountName", disabledOU: "OU=..." }
  move-to-ou          { target: "samAccountName", targetDN: "...", destinationOU: "OU=..." }
  remove-from-group   { target: "samAccountName", groupName: "..." }
  add-to-group        { target: "samAccountName", groupName: "..." }
  list-recycle-bin    {}
  restore-from-recycle-bin { targetDN: "..." }
  Shared mailboxes (on-prem side of a dirsynced mailbox; whatIf: true reads and reports, changes nothing):
  smbx-set-hide-gal   { targetDN, value: true | false | null (null clears the attribute) }
  smbx-set-type-attrs { targetDN, to: "user" | "shared" | {RTD, RRT, RDT} (exact values, for a revert) }
  smbx-delete-object  { targetDN }          Remove-ADObject -Recursive (AD Recycle Bin keeps it)
  restore-object-guid { guid }              Restore-ADObject by objectGUID (revert of smbx-delete-object)
─────────────────────────────────────────────────────────────────────────────
"""

import sys, os, json, re

try:
    import winrm
except ImportError:
    print(json.dumps({'success': False, 'error': 'pywinrm not installed'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'


def get_session(winrm_user, winrm_pass):
    return winrm.Session(
        f'http://{DC_HOST}:5985/wsman',
        auth=(winrm_user, winrm_pass),
        transport='ntlm',
        server_cert_validation='ignore',
        operation_timeout_sec=30,
        read_timeout_sec=35,
    )


def run_ps(session, script):
    result = session.run_ps(script)
    stdout = result.std_out.decode('utf-8', errors='replace').strip()
    stderr = result.std_err.decode('utf-8', errors='replace').strip()
    return stdout, stderr, result.status_code


# PowerShell's tokenizer treats all of these as single-quote delimiters, not
# just ASCII ' (U+2018, U+2019, U+201A, U+201B). Inside a single-quoted
# literal each one is escaped by doubling it.
_PS_SINGLE_QUOTES = ("'", '‘', '’', '‚', '‛')


def _ps_quote(s):
    """Escape a string for embedding in a single-quoted PowerShell literal."""
    for q in _PS_SINGLE_QUOTES:
        s = s.replace(q, q + q)
    return s


def safe(s):
    return _ps_quote(s) if s else ''


def disable_account(session, sam):
    ps = f'''
try {{
    $user = Get-ADUser -Identity '{safe(sam)}' -Properties DistinguishedName,UserAccountControl,Enabled
    $origState = @{{ Enabled = $user.Enabled; UAC = $user.UserAccountControl; DN = $user.DistinguishedName }}
    Disable-ADAccount -Identity '{safe(sam)}' -ErrorAction Stop
    @{{ success = $true; message = "Account disabled"; originalState = $origState; newState = @{{ Enabled = $false }} }} | ConvertTo-Json -Depth 3
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    stdout, stderr, code = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except:
        return {'success': False, 'error': stdout or stderr or 'Unknown error'}


def enable_account(session, sam):
    ps = f'''
try {{
    Enable-ADAccount -Identity '{safe(sam)}' -ErrorAction Stop
    @{{ success = $true; message = "Account enabled"; newState = @{{ Enabled = $true }} }} | ConvertTo-Json -Depth 3
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    stdout, _, _ = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except:
        return {'success': False, 'error': stdout or 'Unknown error'}


def move_to_ou(session, sam, target_dn, destination_ou):
    ps = f'''
try {{
    $user = Get-ADUser -Identity '{safe(sam)}' -Properties DistinguishedName
    $origDN = $user.DistinguishedName
    $origOU = ($origDN -split ',', 2)[1]
    Move-ADObject -Identity $origDN -TargetPath '{safe(destination_ou)}' -ErrorAction Stop
    @{{ success = $true; message = 'Object moved to {safe(destination_ou)}'; originalState = @{{ originalOU = $origOU; originalDN = $origDN }}; newState = @{{ newOU = '{safe(destination_ou)}' }} }} | ConvertTo-Json -Depth 3
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    stdout, _, _ = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except:
        return {'success': False, 'error': stdout or 'Unknown error'}


def move_object_by_dn(session, object_dn, destination_ou):
    ps = f'''
try {{
    Move-ADObject -Identity '{safe(object_dn)}' -TargetPath '{safe(destination_ou)}' -ErrorAction Stop
    @{{ success = $true; message = 'Object moved to {safe(destination_ou)}' }} | ConvertTo-Json
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    stdout, _, _ = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except:
        return {'success': False, 'error': stdout or 'Unknown error'}


def remove_from_group(session, sam, group_name):
    ps = f'''
try {{
    Remove-ADGroupMember -Identity '{safe(group_name)}' -Members '{safe(sam)}' -Confirm:$false -ErrorAction Stop
    @{{ success = $true; message = 'Removed from {safe(group_name)}'; originalState = @{{ groupName = '{safe(group_name)}' }} }} | ConvertTo-Json -Depth 3
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    stdout, _, _ = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except:
        return {'success': False, 'error': stdout or 'Unknown error'}


def add_to_group(session, sam, group_name):
    ps = f'''
try {{
    Add-ADGroupMember -Identity '{safe(group_name)}' -Members '{safe(sam)}' -ErrorAction Stop
    @{{ success = $true; message = 'Added to {safe(group_name)}' }} | ConvertTo-Json
}} catch {{
    $err = $_.Exception.Message
    if ($err -match 'already a member') {{
        @{{ success = $true; message = "Already a member" }} | ConvertTo-Json
    }} else {{
        @{{ success = $false; error = $err }} | ConvertTo-Json
    }}
}}
'''
    stdout, _, _ = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except:
        return {'success': False, 'error': stdout or 'Unknown error'}


def list_recycle_bin(session):
    ps = '''
try {
    $deleted = Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties Name,objectClass,whenChanged,distinguishedName,lastKnownParent | Select-Object -First 100
    $items = @()
    foreach ($obj in $deleted) {
        $items += @{
            name = $obj.Name
            objectClass = $obj.objectClass
            dn = $obj.DistinguishedName
            whenChanged = if ($obj.whenChanged) { $obj.whenChanged.ToString("o") } else { "" }
            lastKnownParent = if ($obj.lastKnownParent) { $obj.lastKnownParent } else { "" }
        }
    }
    @{ success = $true; count = $items.Count; items = $items } | ConvertTo-Json -Depth 3
} catch {
    @{ success = $false; error = $_.Exception.Message } | ConvertTo-Json
}
'''
    stdout, _, _ = run_ps(session, ps)
    try:
        parsed = json.loads(stdout)
        if 'items' in parsed and not isinstance(parsed['items'], list):
            parsed['items'] = [parsed['items']] if parsed['items'] else []
        return parsed
    except:
        return {'success': False, 'error': stdout or 'Unknown error'}


def restore_from_recycle_bin(session, target_dn):
    ps = f'''
try {{
    Restore-ADObject -Identity '{safe(target_dn)}' -ErrorAction Stop
    @{{ success = $true; message = "Object restored from Recycle Bin" }} | ConvertTo-Json
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    stdout, _, _ = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except:
        return {'success': False, 'error': stdout or 'Unknown error'}


# ─── Shared mailbox actions (on-prem attributes of a dirsynced mailbox) ──────
# A dirsynced mailbox's Exchange attributes are owned by on-prem AD (no on-prem Exchange
# here), so hide-from-GAL and the mailbox type are set on the AD object and sync up.
# Values per Microsoft's remote recipient constants:
#   RemoteSharedMailbox: msExchRecipientTypeDetails 34359738368, msExchRemoteRecipientType 100, msExchRecipientDisplayType -2147481850
#   RemoteUserMailbox:   msExchRecipientTypeDetails 2147483648,  msExchRemoteRecipientType 4,   msExchRecipientDisplayType -2147483642
# RTD/RDT are written as given; RRT here is only the typical value: smbx_set_type_attrs flips the shared bits (96)
# of the object's own msExchRemoteRecipientType instead.
SMBX_TYPES = {
    'shared': {'RTD': '34359738368', 'RRT': '100', 'RDT': '-2147481850'},
    'user':   {'RTD': '2147483648',  'RRT': '4',   'RDT': '-2147483642'},
}


def _ps_json(session, ps):
    stdout, stderr, _ = run_ps(session, ps)
    try:
        return json.loads(stdout)
    except Exception:
        return {'success': False, 'error': stdout or stderr or 'Unknown error'}


def _ps_bool(b):
    return '$true' if b else '$false'


def smbx_set_hide_gal(session, dn, value, what_if):
    if value is None:
        change = "Set-ADObject -Identity $o.DistinguishedName -Clear msExchHideFromAddressLists -ErrorAction Stop"
        label = 'cleared'
    else:
        change = "Set-ADObject -Identity $o.DistinguishedName -Replace @{msExchHideFromAddressLists=%s} -ErrorAction Stop" % _ps_bool(value)
        label = 'TRUE' if value else 'FALSE'
    ps = f'''
try {{
    $o = Get-ADObject -Identity '{safe(dn)}' -Properties msExchHideFromAddressLists -ErrorAction Stop
    $orig = $o.msExchHideFromAddressLists
    $origState = @{{ msExchHideFromAddressLists = $orig; DN = $o.DistinguishedName }}
    if ({_ps_bool(what_if)}) {{
        @{{ success = $true; whatIf = $true; message = "Would set msExchHideFromAddressLists {label} (now: $orig)"; originalState = $origState }} | ConvertTo-Json -Depth 3
    }} else {{
        {change}
        @{{ success = $true; message = "msExchHideFromAddressLists {label} (was: $orig); reaches Exchange Online on the next directory sync"; originalState = $origState; newState = @{{ msExchHideFromAddressLists = '{label}' }} }} | ConvertTo-Json -Depth 3
    }}
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    return _ps_json(session, ps)


def smbx_set_type_attrs(session, dn, to, what_if):
    want = SMBX_TYPES.get(to) if isinstance(to, str) else to
    if not isinstance(want, dict) or not all(str(want.get(k, '')).lstrip('-').isdigit() for k in ('RTD', 'RRT', 'RDT')):
        return {'success': False, 'error': 'invalid target type'}
    # Converting requires the object to be a RemoteSharedMailbox now; a revert (exact values) does not.
    # It must also carry all three values, so the recorded original state can be put back exactly.
    guard = ("if ([string]$o.msExchRecipientTypeDetails -ne '34359738368') { throw \"not a remote shared mailbox on-prem (msExchRecipientTypeDetails=$($o.msExchRecipientTypeDetails))\" }; "
             "if ($null -eq $o.msExchRemoteRecipientType -or $null -eq $o.msExchRecipientDisplayType) { throw 'msExchRemoteRecipientType or msExchRecipientDisplayType is not set; convert this one by hand' }"
             if to == 'user' else '')
    rtd, rrt, rdt = want['RTD'], want['RRT'], want['RDT']
    # msExchRemoteRecipientType is a bit field (1 Provision, 4 Migrated, 96 Shared). A type change flips only the shared
    # bits and keeps the rest (97 -> 1, 100 -> 4), as Set-RemoteMailbox -Type would; exact values (a revert) are written as given.
    if to == 'user':
        rrt_ps = "[int64]$o.msExchRemoteRecipientType -band (-bnot 96)"
    elif to == 'shared':
        rrt_ps = "[int64]$o.msExchRemoteRecipientType -bor 96"
    else:
        rrt_ps = f"[int64]'{rrt}'"
    ps = f'''
try {{
    $o = Get-ADObject -Identity '{safe(dn)}' -Properties msExchRecipientTypeDetails,msExchRemoteRecipientType,msExchRecipientDisplayType -ErrorAction Stop
    {guard}
    $origState = @{{ RTD = [string]$o.msExchRecipientTypeDetails; RRT = [string]$o.msExchRemoteRecipientType; RDT = [string]$o.msExchRecipientDisplayType; DN = $o.DistinguishedName }}
    $rrtNew = {rrt_ps}
    $new = @{{ msExchRecipientTypeDetails = [int64]'{rtd}'; msExchRemoteRecipientType = $rrtNew; msExchRecipientDisplayType = [int]'{rdt}' }}
    if ({_ps_bool(what_if)}) {{
        @{{ success = $true; whatIf = $true; message = "Would set RTD/RRT/RDT {rtd}/$rrtNew/{rdt} (now $($origState.RTD)/$($origState.RRT)/$($origState.RDT))"; originalState = $origState }} | ConvertTo-Json -Depth 3
    }} else {{
        Set-ADObject -Identity $o.DistinguishedName -Replace $new -ErrorAction Stop
        @{{ success = $true; message = "On-prem mailbox type attributes set to {rtd}/$rrtNew/{rdt}"; originalState = $origState; newState = @{{ RTD = '{rtd}'; RRT = [string]$rrtNew; RDT = '{rdt}' }} }} | ConvertTo-Json -Depth 3
    }}
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    return _ps_json(session, ps)


def smbx_delete_object(session, dn, what_if):
    ps = f'''
try {{
    $o = Get-ADObject -Identity '{safe(dn)}' -Properties objectGUID,objectClass -ErrorAction Stop
    $origState = @{{ objectGUID = [string]$o.ObjectGUID; DN = $o.DistinguishedName; parent = ($o.DistinguishedName -split ',', 2)[1]; objectClass = [string]$o.ObjectClass }}
    if ({_ps_bool(what_if)}) {{
        @{{ success = $true; whatIf = $true; message = "Would delete $($o.DistinguishedName)"; originalState = $origState }} | ConvertTo-Json -Depth 3
    }} else {{
        Remove-ADObject -Identity $o.ObjectGUID -Recursive -Confirm:$false -ErrorAction Stop
        @{{ success = $true; message = "AD object deleted (AD Recycle Bin keeps it); the mailbox follows on the next directory sync"; originalState = $origState; newState = @{{ state = 'deleted' }} }} | ConvertTo-Json -Depth 3
    }}
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    return _ps_json(session, ps)


def restore_object_guid(session, guid):
    if not re.fullmatch(r'[0-9a-fA-F-]{36}', guid or ''):
        return {'success': False, 'error': 'invalid objectGUID'}
    ps = f'''
try {{
    $o = Get-ADObject -Filter "objectGUID -eq '{guid}'" -IncludeDeletedObjects -Properties isDeleted -ErrorAction Stop
    if (-not $o) {{ throw "object {guid} not found (past the Recycle Bin lifetime?)" }}
    if (-not $o.isDeleted) {{ throw "object {guid} is not deleted" }}
    Restore-ADObject -Identity '{guid}' -ErrorAction Stop
    @{{ success = $true; message = "Object restored from Recycle Bin; the mailbox returns on the next directory sync" }} | ConvertTo-Json
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
    return _ps_json(session, ps)

if __name__ == '__main__':
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
    except Exception as e:
        print(json.dumps({'success': False, 'error': f'Invalid input: {str(e)}'}))
        sys.exit(1)

    action = payload.get('action', '')
    winrm_user = os.environ.get('WINRM_USER', '')
    winrm_pass = os.environ.get('WINRM_PASS', '')

    if not winrm_user or not winrm_pass:
        print(json.dumps({'success': False, 'error': 'WINRM_USER/WINRM_PASS not set'}))
        sys.exit(1)

    try:
        session = get_session(winrm_user, winrm_pass)
    except Exception as e:
        print(json.dumps({'success': False, 'error': f'WinRM connection failed: {str(e)}'}))
        sys.exit(1)

    target = payload.get('target', '')
    target_dn = payload.get('targetDN', '')

    if action == 'disable-account':
        result = disable_account(session, target)
    elif action == 'enable-account':
        result = enable_account(session, target)
    elif action == 'move-to-disabled':
        result = move_to_ou(session, target, target_dn, payload.get('disabledOU', ''))
    elif action == 'move-to-ou':
        if target_dn:
            result = move_object_by_dn(session, target_dn, payload.get('destinationOU', ''))
        else:
            result = move_to_ou(session, target, '', payload.get('destinationOU', ''))
    elif action == 'remove-from-group':
        result = remove_from_group(session, target, payload.get('groupName', ''))
    elif action == 'add-to-group':
        result = add_to_group(session, target, payload.get('groupName', ''))
    elif action == 'list-recycle-bin':
        result = list_recycle_bin(session)
    elif action == 'restore-from-recycle-bin':
        result = restore_from_recycle_bin(session, target_dn)
    elif action == 'smbx-set-hide-gal':
        result = smbx_set_hide_gal(session, target_dn, payload.get('value'), bool(payload.get('whatIf')))
    elif action == 'smbx-set-type-attrs':
        result = smbx_set_type_attrs(session, target_dn, payload.get('to'), bool(payload.get('whatIf')))
    elif action == 'smbx-delete-object':
        result = smbx_delete_object(session, target_dn, bool(payload.get('whatIf')))
    elif action == 'restore-object-guid':
        result = restore_object_guid(session, payload.get('guid', ''))
    else:
        result = {'success': False, 'error': f'Unknown action: {action}'}

    print(json.dumps(result))
