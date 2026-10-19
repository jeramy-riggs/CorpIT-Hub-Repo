#!/usr/bin/env python3
"""
Password Reset - sets AD user password via WinRM/PowerShell
Usage: TARGET_USER=<username> NEW_PASSWORD=<password> [FORCE_CHANGE=0|1] python3 password-reset.py
       (username may also be argv[1]; the password is NEVER read from argv --
        argv is world-readable via /proc/<pid>/cmdline)
Reads WINRM_USER and WINRM_PASS from environment variables
FORCE_CHANGE: 1 = user must change password at next logon (WARNING: can break Okta sync)
              0 or omitted = do NOT force change (default)
"""
import sys
import os
import json

try:
    import winrm
except ImportError:
    print(json.dumps({'error': 'pywinrm not installed'}))
    sys.exit(1)

DC_HOST = '10.9.64.80'

def reset_password(username, new_password, winrm_user, winrm_pass, force_change=False):
    try:
        session = winrm.Session(
            f'http://{DC_HOST}:5985/wsman',
            auth=(winrm_user, winrm_pass),
            transport='ntlm',
            server_cert_validation='ignore',
            operation_timeout_sec=30,
            read_timeout_sec=35,
        )

        # Escape single quotes for PowerShell
        safe_pass = new_password.replace("'", "''")
        safe_user = username.replace("'", "''")
        force_val = '$true' if force_change else '$false'

        ps_script = f'''
try {{
    $secPass = ConvertTo-SecureString '{safe_pass}' -AsPlainText -Force
    Set-ADAccountPassword -Identity '{safe_user}' -Reset -NewPassword $secPass -ErrorAction Stop
    Set-ADUser -Identity '{safe_user}' -ChangePasswordAtLogon {force_val} -ErrorAction Stop
    @{{ success = $true; message = "Password reset successfully for {safe_user}" }} | ConvertTo-Json
}} catch {{
    @{{ success = $false; error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
        result = session.run_ps(ps_script)

        stdout = result.std_out.decode('utf-8', errors='replace').strip()
        stderr = result.std_err.decode('utf-8', errors='replace').strip()

        if result.status_code != 0 and not stdout:
            return {'success': False, 'error': f'PowerShell error: {stderr}'}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            if 'success' in stdout.lower():
                return {'success': True, 'message': f'Password reset for {username}'}
            return {'success': False, 'error': stdout or stderr or 'Unknown error'}

    except winrm.exceptions.InvalidCredentialsError:
        return {'success': False, 'error': 'WinRM authentication failed - check WINRM_USER and WINRM_PASS'}
    except winrm.exceptions.WinRMTransportError as e:
        return {'success': False, 'error': f'WinRM connection failed: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Unexpected error: {str(e)}'}


if __name__ == '__main__':
    # pw-on-argv: the password is accepted ONLY from the environment (set by
    # identity-routes.js). argv[1] is kept as a manual-CLI fallback for the
    # username only; anything beyond argv[1] is refused so the old
    # "<username> <password>" form can never put a secret on the command line.
    if len(sys.argv) > 2:
        print(json.dumps({'success': False, 'error': 'Refusing extra command-line arguments: the password is never read from argv. Use TARGET_USER / NEW_PASSWORD / FORCE_CHANGE in the environment.'}))
        sys.exit(1)

    username = (os.environ.get('TARGET_USER') or (sys.argv[1] if len(sys.argv) > 1 else '')).strip()
    new_password = os.environ.get('NEW_PASSWORD', '')
    force_change = (os.environ.get('FORCE_CHANGE') or '0').strip() == '1'

    if not username:
        print(json.dumps({'success': False, 'error': 'Usage: TARGET_USER=<username> NEW_PASSWORD=<password> [FORCE_CHANGE=0|1] password-reset.py'}))
        sys.exit(1)
    if not new_password:
        print(json.dumps({'success': False, 'error': 'NEW_PASSWORD not set in environment (the password is never read from argv)'}))
        sys.exit(1)
    winrm_user = os.environ.get('WINRM_USER', '')
    winrm_pass = os.environ.get('WINRM_PASS', '')

    if not winrm_user or not winrm_pass:
        print(json.dumps({'success': False, 'error': 'WINRM_USER and WINRM_PASS not set'}))
        sys.exit(1)

    result = reset_password(username, new_password, winrm_user, winrm_pass, force_change)
    print(json.dumps(result))
