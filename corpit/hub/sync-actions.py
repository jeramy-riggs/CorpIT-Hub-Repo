#!/usr/bin/env python3
"""
sync-actions.py — WinRM-driven AD replication + AAD Connect delta sync for the
identity-diag "Force Replicate & Sync" control.

Subcommands (invoked by identity-routes.js via execFile):
  ad-status  <sam>   Read-only: per-DC whenChanged/uSNChanged for one user, so the
                     modal can show whether the object has converged across DCs.
  replicate  <sam>   Force single-object replication of that user's AD object from
                     the primary DC (the LDAP write target) to every other DC.
  entra-delta        Trigger a delta sync cycle on the active AAD Connect server.

Reads WINRM_USER / WINRM_PASS from the environment (same creds the existing
unlock / lockout-source actions use). Prints a single JSON object to stdout.
"""
import sys
import os
import json

try:
    import winrm
except ImportError:
    print(json.dumps({'success': False, 'error': 'pywinrm not installed — run: pip install pywinrm --break-system-packages'}))
    sys.exit(1)

# Domain topology (discovered 2026-08-31). Primary = the DC the app binds to for
# LDAP writes, so it is the authoritative source for forced replication.
PRIMARY_DC = 'adcoredc16009.NRPI.LOCAL'
ALL_DCS = [
    {'name': 'ADCOREDC16009', 'host': 'adcoredc16009.NRPI.LOCAL', 'ip': '10.9.64.80',  'site': 'AWS-ADC'},
    {'name': 'DCW13SNA01US',  'host': 'dcw13sna01us.NRPI.LOCAL',  'ip': '10.20.10.23', 'site': 'SNA01'},
    {'name': 'ADCOHIDC16009', 'host': 'ADCOHIDC16009.NRPI.LOCAL', 'ip': '10.10.64.80', 'site': 'AWS-ADCDR'},
]
# Active (non-staging) AAD Connect server, confirmed StagingModeEnabled=false.
AADC_HOST = '10.9.64.146'  # SVC01AWSW2US


def session(host):
    user = os.environ.get('WINRM_USER')
    pw = os.environ.get('WINRM_PASS')
    if not user or not pw:
        raise RuntimeError('WINRM credentials not configured')
    return winrm.Session(
        f'http://{host}:5985/wsman',
        auth=(user, pw),
        transport='ntlm',
        server_cert_validation='ignore',
        operation_timeout_sec=55,
        read_timeout_sec=60,
    )


def run_ps(host, script):
    r = session(host).run_ps(script)
    out = r.std_out.decode('utf-8', 'replace').strip()
    if r.status_code != 0 and not out:
        err = r.std_err.decode('utf-8', 'replace')
        # Strip PowerShell CLIXML progress noise if that's all we got.
        raise RuntimeError(err.strip()[:400] or 'PowerShell exited non-zero')
    return out


def _sam_literal(sam):
    # Only allow characters valid in a sAMAccountName; reject anything that could
    # break out of the single-quoted PowerShell string.
    import re
    if not re.match(r'^[A-Za-z0-9._\-$]{1,64}$', sam or ''):
        raise ValueError('invalid sAMAccountName')
    return sam


def _ps_local_getuser(sam):
    # Runs on each DC via its own WinRM session: query the LOCAL directory (the DC
    # answering is authoritative for its own replica), so we see per-DC convergence.
    return f'''
$ErrorActionPreference='Stop'
try {{
  $u = Get-ADUser -Identity '{sam}' -Properties whenChanged,uSNChanged,pwdLastSet,memberOf,lockoutTime -ErrorAction Stop
  [ordered]@{{
    ok          = $true
    whenChanged = if ($u.whenChanged) {{ $u.whenChanged.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }} else {{ $null }}
    uSNChanged  = [string]$u.uSNChanged
    groupCount  = @($u.memberOf).Count
    lockedOut   = ($u.lockoutTime -ne $null -and $u.lockoutTime -ne 0)
  }} | ConvertTo-Json -Compress
}} catch {{
  [ordered]@{{ ok = $false; error = $_.Exception.Message }} | ConvertTo-Json -Compress
}}'''


def ad_status(sam):
    sam = _sam_literal(sam)
    rows = []
    for dc in ALL_DCS:
        row = {'dc': dc['host'], 'name': dc['name'], 'site': dc['site']}
        try:
            out = run_ps(dc['ip'], _ps_local_getuser(sam))
            row.update(json.loads(out))
        except Exception as e:
            row.update({'ok': False, 'error': str(e)[:200]})
        rows.append(row)
    # uSNChanged is a per-DC counter and never matches across DCs, and whenChanged
    # is stamped locally when each DC applies a write — neither is a convergence
    # oracle. The fields that reflect the changes THIS tool makes (unlock,
    # group-add) are lockedOut and groupCount; agreement on those across every
    # reachable DC is the honest "the change has landed everywhere" signal.
    reachable = [r for r in rows if r.get('ok')]
    states = {(r.get('lockedOut'), r.get('groupCount')) for r in reachable}
    return json.dumps({
        'success': True,
        'rows': rows,
        'inSync': (len(states) <= 1 and len(reachable) == len(ALL_DCS)),
        'reachableCount': len(reachable),
        'dcCount': len(ALL_DCS),
    })


def replicate(sam):
    sam = _sam_literal(sam)
    # Resolve the DN once from the primary (LDAP write target = source of truth).
    dn_out = run_ps(PRIMARY_DC, f'''
$ErrorActionPreference='Stop'
(Get-ADUser -Identity '{sam}' -ErrorAction Stop).DistinguishedName''')
    dn = dn_out.strip().splitlines()[-1].strip() if dn_out else ''
    if not dn or not dn.upper().startswith('CN='):
        return json.dumps({'success': False, 'error': 'could not resolve DN for ' + sam})

    # Force single-object replication with repadmin (DRSUAPI/RPC) run ON each
    # destination DC. Unlike Sync-ADObject (ADWS), RPC rides the DCs' existing
    # replication path, so it works despite cross-DC ADWS being firewalled here.
    src = PRIMARY_DC
    results = []
    for dc in ALL_DCS:
        if dc['host'].lower() == PRIMARY_DC.lower():
            continue
        dest = dc['host']
        dn_lit = dn.replace("'", "''")   # single quotes are literal in PS; '' is the escape
        ps = (
            "$dn = '" + dn_lit + "'; "
            "$o = repadmin /replsingleobj " + dest + " " + src + ' $dn 2>&1 | Out-String; '
            '$code = $LASTEXITCODE; '
            "@{ dest = '" + dest + "'; exit = $code; out = $o.Trim() } | ConvertTo-Json -Compress"
        )
        try:
            parsed = json.loads(run_ps(dc['ip'], ps))
            ok = (parsed.get('exit') == 0) and ('successfully replicated' in (parsed.get('out') or '').lower())
            results.append({'dest': dest, 'ok': ok, 'detail': (parsed.get('out') or '')[:300]})
        except Exception as e:
            results.append({'dest': dest, 'ok': False, 'error': str(e)[:200]})
    any_fail = any(not r.get('ok') for r in results)
    return json.dumps({'success': (not any_fail), 'dn': dn, 'source': src, 'results': results})


def entra_delta():
    ps = '''
$ErrorActionPreference='Stop'
try {
  Import-Module ADSync -ErrorAction Stop
  $sched = Get-ADSyncScheduler
  if ($sched.SyncCycleInProgress) {
    @{ success = $true; alreadyRunning = $true; message = 'A sync cycle is already in progress' } | ConvertTo-Json
  } else {
    $r = Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
    @{ success = $true; alreadyRunning = $false; result = [string]$r.Result } | ConvertTo-Json
  }
} catch {
  @{ success = $false; error = $_.Exception.Message } | ConvertTo-Json
}
'''
    return run_ps(AADC_HOST, ps)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'success': False, 'error': 'usage: sync-actions.py <ad-status|replicate|entra-delta> [sam]'}))
        sys.exit(2)
    cmd = sys.argv[1]
    try:
        if cmd == 'ad-status':
            print(ad_status(sys.argv[2]))
        elif cmd == 'replicate':
            print(replicate(sys.argv[2]))
        elif cmd == 'entra-delta':
            print(entra_delta())
        else:
            print(json.dumps({'success': False, 'error': 'unknown command: ' + cmd}))
            sys.exit(2)
    except IndexError:
        print(json.dumps({'success': False, 'error': 'missing sAMAccountName argument'}))
        sys.exit(2)
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)[:400]}))
        sys.exit(1)


if __name__ == '__main__':
    main()
