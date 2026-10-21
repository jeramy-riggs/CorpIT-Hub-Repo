#!/usr/bin/env python3
"""
cert-watchtower-ca-scan-helper.py
Cert Watchtower v1.2.1 — CA Issued Cert Scanner

Connects to a Windows CA server via WinRM, runs certutil -view to enumerate
issued (non-revoked) certificates, and returns them as JSON on stdout.

Usage:
  python3 cert-watchtower-ca-scan-helper.py \
    --host pki04awsw2us.nrpi.local \
    --ca-name NRPI-PKI04AWSW2US-CA \
    --port 5985 --transport ntlm --timeout 120

Environment:
  WINRM_USER  domain\\username
  WINRM_PASS  password

Output (stdout, always valid JSON):
  Success: {"ok": true, "certs": [...], "count": N, "duration_ms": N}
  Failure: {"ok": false, "error": "...", "duration_ms": N}
"""

import sys, os, json, argparse, time, re
from datetime import datetime

try:
    import winrm
except ImportError:
    print(json.dumps({"ok": False, "error": "pywinrm not installed"}))
    sys.exit(1)


# Scan-target policy (hotfix-bundle3 2026-10-21, F20/F21). Mirrors
# cert-watchtower-guards.js / the WinRM helper: never 'basic', *.nrpi.local or
# 10.x hosts only, https validated against the NRPI CA chain.
ALLOWED_TRANSPORTS = ('ntlm', 'kerberos', 'credssp')
# /etc/ssl/certs copy is missing on corpit A/B; the hub's own copy shipped 10-20.
NRPI_CA_BUNDLE = next((p for p in ('/etc/ssl/certs/nrpi-ca-chain.pem',
                                  '/var/www/corpit-hub-api/certs/nrpi-ca-chain.pem')
                       if os.path.isfile(p)), '/etc/ssl/certs/nrpi-ca-chain.pem')
_HOST_NAME_RE = re.compile(
    r'(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+nrpi\.local', re.IGNORECASE | re.ASCII)
_HOST_IPV4_RE = re.compile(r'10\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', re.ASCII)


def is_allowed_host(host):
    if not isinstance(host, str):
        return False
    h = host.strip()
    if not h or len(h) > 255:
        return False
    if _HOST_NAME_RE.fullmatch(h):
        return True
    m = _HOST_IPV4_RE.fullmatch(h)
    return bool(m) and all(int(o) <= 255 for o in m.groups())


def build_protocol(host, port, transport, use_ssl, user, password, timeout):
    """pywinrm Protocol for the CA host; ValueError if outside policy."""
    if transport not in ALLOWED_TRANSPORTS:
        raise ValueError(f"transport '{transport}' is not allowed")
    if not is_allowed_host(host):
        raise ValueError('host must be *.nrpi.local or a 10.x address')
    return winrm.Protocol(
        endpoint=f'{"https" if use_ssl else "http"}://{host.strip()}:{port}/wsman',
        transport=transport,
        username=user,
        password=password,
        server_cert_validation='validate',
        ca_trust_path=NRPI_CA_BUNDLE,
        operation_timeout_sec=timeout,
        read_timeout_sec=timeout + 10,
    )


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--host',      required=True)
    p.add_argument('--ca-name',   required=True)
    p.add_argument('--port',      type=int, default=5985)
    p.add_argument('--transport', default='ntlm',
                   choices=list(ALLOWED_TRANSPORTS))
    p.add_argument('--timeout',   type=int, default=120)
    p.add_argument('--ssl',       action='store_true')
    return p.parse_args()


def strip_quotes(s):
    """Remove surrounding double quotes that certutil adds to string values."""
    if s and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def parse_certutil_date(s):
    """
    Parse certutil date strings. Observed format: "3/19/2024 8:33 PM"
    Returns ISO 8601 string or None.
    """
    if not s or s in ('--', 'EMPTY', ''):
        return None
    s = strip_quotes(s).strip()
    formats = [
        '%m/%d/%Y %I:%M %p',    # 3/19/2024 8:33 PM
        '%m/%d/%Y %I:%M:%S %p', # 3/19/2024 8:33:00 PM
        '%m/%d/%Y %H:%M',       # 3/19/2024 20:33
        '%m/%d/%Y %H:%M:%S',    # 3/19/2024 20:33:00
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M',
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt).strftime('%Y-%m-%dT%H:%M:%S')
        except ValueError:
            continue
    return s  # return raw rather than None for debugging


def parse_certutil_output(raw):
    """
    Parse certutil -view columnar output into a list of cert dicts.

    Actual field labels (localized names) from the output:
      Issued Request ID       -> request_id  (hex e.g. 0x3)
      Requester Name          -> requester_name
      Certificate Template    -> cert_template (may include OID prefix)
      Issued Common Name      -> subject_cn  ("EMPTY" = None)
      Certificate Effective Date -> not_before
      Certificate Expiration Date -> not_after
      Serial Number           -> serial_number
    """
    certs = []

    # Split on "Row N:" boundaries (handles \r\n and \n)
    blocks = re.split(r'\r?\n(?=Row \d+:)', raw)

    for block in blocks:
        if not block.strip().startswith('Row '):
            continue

        cert = {}
        for line in block.splitlines():
            line = line.strip()
            if not line or ':' not in line:
                continue
            key, _, val = line.partition(':')
            key = key.strip()
            val = val.strip()

            if key == 'Issued Request ID':
                # Convert hex (0x3) or decimal to int string
                try:
                    cert['request_id'] = str(int(val, 16)) if val.startswith('0x') else str(int(val))
                except ValueError:
                    cert['request_id'] = val

            elif key == 'Requester Name':
                cert['requester_name'] = strip_quotes(val) or None

            elif key == 'Certificate Template':
                # Observed formats from certutil:
                #   "WebServer"
                #   "1.3.6.1.4.1.311..." Directory Email Replication
                v = val.strip()
                # OID in quotes followed by display name: "1.3.6..." Display Name
                oid_quoted = re.match(r'^"([\d.]+)"\s+(.+)$', v)
                if oid_quoted:
                    cert['cert_template'] = oid_quoted.group(2).strip()
                else:
                    # Plain quoted string: "WebServer"
                    plain_quoted = re.match(r'^"(.+)"$', v)
                    if plain_quoted:
                        cert['cert_template'] = plain_quoted.group(1)
                    else:
                        cert['cert_template'] = v or None

            elif key == 'Issued Common Name':
                cn = strip_quotes(val)
                cert['subject_cn'] = None if cn in ('EMPTY', '', '--') else cn

            elif key == 'Certificate Effective Date':
                cert['not_before'] = parse_certutil_date(val)

            elif key == 'Certificate Expiration Date':
                cert['not_after'] = parse_certutil_date(val)

            elif key == 'Serial Number':
                sn = strip_quotes(val).upper().replace(' ', '')
                cert['serial_number'] = sn if sn else None

        if cert.get('serial_number'):
            certs.append(cert)

    return certs


# H-8 defense in depth: host and ca_name are interpolated into a cmd.exe
# command line on the CA host. Refuse anything outside a conservative set
# (no quotes, ampersand, pipe, semicolons, backslash, etc.). The API layer
# enforces the same pattern on write; this guards the DB -> command path.
SAFE_CMD_ARG_RE = re.compile(r'[A-Za-z0-9._ -]{1,255}')


def validate_cmd_arg(name, value):
    if not isinstance(value, str) or not SAFE_CMD_ARG_RE.fullmatch(value):
        raise ValueError(
            f'{name} contains disallowed characters '
            f'(allowed: letters, digits, space, . _ - ; max 255)'
        )


def build_certutil_cmd(host, ca_name):
    validate_cmd_arg('host', host)
    validate_cmd_arg('ca_name', ca_name)
    config  = f'{host}\\{ca_name}'
    columns = 'RequestID,RequesterName,CertificateTemplate,CommonName,NotBefore,NotAfter,SerialNumber'
    return (
        f'certutil -config "{config}" '
        f'-view -restrict "Disposition=20" '
        f'-out "{columns}"'
    )


def main():
    started = time.time()
    args    = parse_args()

    user     = os.environ.get('WINRM_USER', '')
    password = os.environ.get('WINRM_PASS', '')
    if not user or not password:
        print(json.dumps({
            "ok": False,
            "error": "WINRM_USER and WINRM_PASS must be set",
            "duration_ms": int((time.time() - started) * 1000)
        }))
        sys.exit(1)

    try:
        protocol = build_protocol(args.host, args.port, args.transport, args.ssl,
                                  user, password, args.timeout)

        cmd        = build_certutil_cmd(args.host, args.ca_name)
        shell_id   = protocol.open_shell()
        command_id = protocol.run_command(shell_id, 'cmd.exe', ['/c', cmd])
        stdout_b, stderr_b, rc = protocol.get_command_output(shell_id, command_id)
        protocol.cleanup_command(shell_id, command_id)
        protocol.close_shell(shell_id)

        stdout = stdout_b.decode('utf-8', errors='replace')
        stderr = stderr_b.decode('utf-8', errors='replace')

        if rc != 0 and not stdout.strip():
            print(json.dumps({
                "ok": False,
                "error": f"certutil exited {rc}: {(stderr or stdout)[:500]}",
                "duration_ms": int((time.time() - started) * 1000)
            }))
            sys.exit(0)

        certs = parse_certutil_output(stdout)
        print(json.dumps({
            "ok": True,
            "certs": certs,
            "count": len(certs),
            "duration_ms": int((time.time() - started) * 1000)
        }))

    except Exception as e:
        print(json.dumps({
            "ok": False,
            "error": str(e),
            "duration_ms": int((time.time() - started) * 1000)
        }))
        sys.exit(0)


if __name__ == '__main__':
    main()
