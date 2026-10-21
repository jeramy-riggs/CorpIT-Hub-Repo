#!/usr/bin/env python3
"""
Cert Watchtower — WinRM helper.

Connects to a single Windows host via WinRM, scans configured cert stores,
optionally enumerates IIS bindings, and prints the findings to stdout as JSON.

Designed to be invoked by the Node scanner script. Stays a single-purpose
tool — one host per invocation, JSON in/out, exit code reflects success.

USAGE:
    python3 cert-watchtower-winrm-helper.py --host SERVER01.nrpi.local \\
        [--port 5985] [--transport ntlm] [--ssl] \\
        [--stores 'LocalMachine\\My,LocalMachine\\WebHosting'] \\
        [--scan-iis] [--timeout 60]

ENVIRONMENT:
    WINRM_USER  — required, e.g. NRPI\\svcuser
    WINRM_PASS  — required

EXIT CODES:
    0 = success, JSON on stdout
    1 = connection / auth / runtime error (details on stderr)
    2 = invalid arguments

OUTPUT (stdout, JSON):
{
    "ok": true,
    "fqdn":          "<reported by Windows>",
    "hostname":      "<short name>",
    "os_version":    "<Caption + Version>",
    "store_count":   3,
    "iis_count":     2,
    "findings":      [ { ...finding objects matching the API schema... } ]
}
"""

import argparse
import base64
import json
import os
import re
import sys
import traceback

try:
    import winrm  # pywinrm
except ImportError:
    print(json.dumps({"ok": False, "error": "pywinrm not installed (apt install python3-winrm)"}),
          file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# The PowerShell that actually runs on the remote box.
#
# Returns a single JSON document on stdout describing all certs found in the
# requested stores plus any IIS bindings (if requested).
#
# Designed to be tolerant: per-cert errors are caught and surfaced in the
# finding's `error` field rather than failing the whole scan.
# ---------------------------------------------------------------------------
PS_SCRIPT_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$Stores  = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__STORES_B64__')) -split ','
$ScanIis = [bool]__SCAN_IIS__

function Get-FingerprintSha256 {
    param([Parameter(Mandatory)]$Cert)
    try {
        $h = [System.Security.Cryptography.SHA256]::Create()
        $bytes = $h.ComputeHash($Cert.RawData)
        return ($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ''
    } catch { return $null }
}

function Get-CnFromDn {
    param([string]$Dn)
    if (-not $Dn) { return $null }
    foreach ($part in ($Dn -split ',\s*')) {
        if ($part -match '^CN=(.*)$') { return $Matches[1] }
    }
    return $null
}

function Get-CertSANs {
    param([Parameter(Mandatory)]$Cert)
    $sans = @()
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq '2.5.29.17') {
            $raw = $ext.Format($true)
            foreach ($line in $raw -split "`r?`n") {
                $line = $line.Trim()
                if ($line) { $sans += $line }
            }
        }
    }
    return ,$sans
}

function ConvertTo-Finding {
    param(
        [Parameter(Mandatory)]$Cert,
        [Parameter(Mandatory)][string]$StoreName,
        [string]$StoreLocation = $null
    )
    $keyAlg = $null; $keySize = $null
    try { $keyAlg = $Cert.PublicKey.Oid.FriendlyName } catch {}
    try { $keySize = $Cert.PublicKey.Key.KeySize } catch {}
    return [pscustomobject]@{
        store_name           = $StoreName
        store_location       = $StoreLocation
        thumbprint_sha1      = $Cert.Thumbprint
        fingerprint_sha256   = (Get-FingerprintSha256 -Cert $Cert)
        serial_number        = $Cert.SerialNumber
        subject              = $Cert.Subject
        subject_cn           = (Get-CnFromDn -Dn $Cert.Subject)
        issuer               = $Cert.Issuer
        issuer_cn            = (Get-CnFromDn -Dn $Cert.Issuer)
        san_list             = (Get-CertSANs -Cert $Cert)
        not_before           = $Cert.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        not_after            = $Cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        has_private_key      = $Cert.HasPrivateKey
        is_self_signed       = ($Cert.Subject -eq $Cert.Issuer)
        key_algorithm        = $keyAlg
        key_size             = $keySize
        signature_algorithm  = $Cert.SignatureAlgorithm.FriendlyName
    }
}

$findings = @()
$storeCount = 0
$iisCount   = 0

foreach ($store in $Stores) {
    $store = $store.Trim()
    if (-not $store) { continue }
    $path = "Cert:\$store"
    if (-not (Test-Path $path)) { continue }
    try {
        foreach ($c in (Get-ChildItem -Path $path -ErrorAction Stop)) {
            try {
                $findings += (ConvertTo-Finding -Cert $c -StoreName $store)
                $storeCount++
            } catch {
                # Skip a single failed cert without aborting
                Write-Warning ("Skipped cert in {0}: {1}" -f $store, $_.Exception.Message)
            }
        }
    } catch {
        Write-Warning ("Failed to read store {0}: {1}" -f $store, $_.Exception.Message)
    }
}

if ($ScanIis -and (Get-Module -ListAvailable -Name WebAdministration)) {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        foreach ($site in (Get-Website)) {
            foreach ($b in $site.Bindings.Collection) {
                if ($b.protocol -ne 'https') { continue }
                if ([string]::IsNullOrWhiteSpace($b.certificateHash)) { continue }
                $thumb = $b.certificateHash.ToUpper()
                $sn = if ($b.certificateStoreName) { "LocalMachine\$($b.certificateStoreName)" } else { 'LocalMachine\My' }
                $cp = "Cert:\$sn\$thumb"
                if (-not (Test-Path $cp)) { continue }
                try {
                    $cert = Get-Item -Path $cp
                    $findings += (ConvertTo-Finding -Cert $cert -StoreName 'IIS Binding' `
                                    -StoreLocation "$($site.Name):$($b.bindingInformation)")
                    $iisCount++
                } catch {
                    Write-Warning ("Skipped IIS binding {0}: {1}" -f $b.bindingInformation, $_.Exception.Message)
                }
            }
        }
    } catch {
        Write-Warning ("IIS scan failed: {0}" -f $_.Exception.Message)
    }
}

# Host info
$os = Get-CimInstance Win32_OperatingSystem
$reportedFqdn = try { ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName } catch { $env:COMPUTERNAME }

$result = [pscustomobject]@{
    ok          = $true
    fqdn        = $reportedFqdn
    hostname    = $env:COMPUTERNAME
    os_version  = "$($os.Caption) $($os.Version)"
    store_count = $storeCount
    iis_count   = $iisCount
    findings    = $findings
}

# Compress=$true would emit minified JSON but isn't available on PS5.1.
# Default ConvertTo-Json depth is 2, way too shallow. Use -Depth 10.
$result | ConvertTo-Json -Depth 10
"""


# ---------------------------------------------------------------------------
# Scan-target policy (hotfix-bundle3 2026-10-21, F19/F20/F21). Mirrors
# cert-watchtower-guards.js so a DB row saved before the API checks existed
# still cannot get the WinRM credential sent somewhere it shouldn't go.
# ---------------------------------------------------------------------------
ALLOWED_TRANSPORTS = ("ntlm", "kerberos", "credssp")   # never 'basic'
# /etc/ssl/certs copy is missing on corpit A/B; the hub's own copy shipped 10-20.
NRPI_CA_BUNDLE = next((p for p in ("/etc/ssl/certs/nrpi-ca-chain.pem",
                                  "/var/www/corpit-hub-api/certs/nrpi-ca-chain.pem")
                       if os.path.isfile(p)), "/etc/ssl/certs/nrpi-ca-chain.pem")
_HOST_NAME_RE = re.compile(
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+nrpi\.local", re.IGNORECASE | re.ASCII)
_HOST_IPV4_RE = re.compile(r"10\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", re.ASCII)
_STORE_ITEM = r"(?:LocalMachine|CurrentUser)\\[A-Za-z0-9 _-]+"
_STORES_RE = re.compile(
    rf"\s*{_STORE_ITEM}\s*(?:,\s*{_STORE_ITEM}\s*)*", re.IGNORECASE | re.ASCII)


def is_allowed_host(host) -> bool:
    if not isinstance(host, str):
        return False
    h = host.strip()
    if not h or len(h) > 255:
        return False
    if _HOST_NAME_RE.fullmatch(h):
        return True
    m = _HOST_IPV4_RE.fullmatch(h)
    return bool(m) and all(int(o) <= 255 for o in m.groups())


def is_valid_stores(stores) -> bool:
    return (isinstance(stores, str) and len(stores) <= 512
            and _STORES_RE.fullmatch(stores) is not None)


def build_session(host: str, port: int, transport: str, use_ssl: bool,
                  username: str, password: str, timeout_s: int) -> "winrm.Session":
    """Construct a pywinrm Session with the right URL/transport.

    Refuses (ValueError) a transport or host outside policy. Over https the
    server cert is validated against the NRPI CA chain.
    """
    if transport not in ALLOWED_TRANSPORTS:
        raise ValueError(f"transport '{transport}' is not allowed")
    if not is_allowed_host(host):
        raise ValueError("host must be *.nrpi.local or a 10.x address")
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host.strip()}:{port}"
    return winrm.Session(
        url,
        auth=(username, password),
        transport=transport,
        server_cert_validation="validate",
        ca_trust_path=NRPI_CA_BUNDLE,
        operation_timeout_sec=timeout_s,
        read_timeout_sec=timeout_s + 10
    )


def render_ps_script(stores: str, scan_iis: bool) -> str:
    """Substitute the runtime values into the PowerShell template.

    pywinrm encodes the script as base64 in `powershell -encodedcommand`,
    which is subject to the Windows command-line length limit (~8K chars).
    Strip comments and blank lines before substitution to stay well under it.

    `stores` must pass is_valid_stores (ValueError otherwise) and goes into the
    script only as base64, never as PowerShell string text.
    """
    if not is_valid_stores(stores):
        raise ValueError("stores invalid")
    # Stripping rules: drop full-line `#` comments and blank lines.
    # Don't touch lines with code; PowerShell single-line comments are rare
    # in this script and trailing-comment stripping is risky (could break
    # strings that contain `#`).
    lines = []
    for line in PS_SCRIPT_TEMPLATE.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        lines.append(line)
    compact = "\n".join(lines)

    return (compact
            .replace("__STORES_B64__",
                     base64.b64encode(stores.encode("utf-8")).decode("ascii"))
            .replace("__SCAN_IIS__", "1" if scan_iis else "0"))


def main() -> int:
    p = argparse.ArgumentParser(description="Cert Watchtower WinRM helper")
    p.add_argument("--host", required=True, help="Hostname or IP of target Windows server")
    p.add_argument("--port", type=int, default=5985)
    p.add_argument("--transport", default="ntlm",
                   choices=list(ALLOWED_TRANSPORTS))
    p.add_argument("--ssl", action="store_true", help="Use HTTPS WinRM (5986 typical)")
    p.add_argument("--stores", default="LocalMachine\\My",
                   help="Comma-separated store list (e.g. 'LocalMachine\\My,LocalMachine\\WebHosting')")
    p.add_argument("--scan-iis", action="store_true", default=False)
    p.add_argument("--timeout", type=int, default=60)
    args = p.parse_args()

    username = os.environ.get("WINRM_USER")
    password = os.environ.get("WINRM_PASS")
    if not username or not password:
        print(json.dumps({"ok": False, "error": "WINRM_USER and WINRM_PASS must be set"}),
              file=sys.stderr)
        return 2

    # Policy check before anything is sent; JSON on stdout so the cron and
    # scan-now record the reason on the agent row.
    if not is_allowed_host(args.host):
        print(json.dumps({"ok": False, "host": args.host,
                          "error": "refused: host must be *.nrpi.local or a 10.x address"}))
        return 2
    if not is_valid_stores(args.stores):
        print(json.dumps({"ok": False, "host": args.host,
                          "error": "refused: --stores invalid"}))
        return 2

    session = build_session(args.host, args.port, args.transport, args.ssl,
                            username, password, args.timeout)
    ps = render_ps_script(args.stores, args.scan_iis)

    # STRATEGY: stage-as-file.
    # The cmdline `-EncodedCommand` route hits Windows' 8K limit; the stdin
    # `-Command -` route (with chunked send) silently swallowed our script
    # in testing. The reliable path is:
    #   1. Open a shell, run a small bootstrap that creates a temp .ps1 file
    #      whose contents come from a base64 string we pass on the cmdline.
    #   2. Run powershell.exe -File <that path>.
    #   3. Clean up the temp file.
    # The base64 of our script is ~6KB which fits cleanly in an arg.
    protocol = session.protocol
    shell_id = None
    try:
        shell_id = protocol.open_shell()

        # Step 1: drop the script onto the remote box as a temp .ps1 file
        # We base64-encode UTF-8 to avoid quoting/escaping pain in the cmdline.
        script_b64 = base64.b64encode(ps.encode("utf-8")).decode("ascii")
        # Random-ish filename to avoid clashes if multiple scans race
        temp_name = f"cwt-scan-{os.getpid()}-{int(__import__('time').time()*1000)}.ps1"
        # Bootstrap: decode base64 (UTF-8) and write to $env:TEMP\<file>
        bootstrap = (
            f"$b='{script_b64}';"
            f"$bytes=[Convert]::FromBase64String($b);"
            f"$path=Join-Path $env:TEMP '{temp_name}';"
            f"[IO.File]::WriteAllBytes($path,$bytes);"
            f"Write-Output $path"
        )
        # `powershell -Command "<bootstrap>"` — the bootstrap itself is short,
        # the long part (base64 script) goes inside it but as a string literal
        # which doesn't have the same encoding-balloon issue as -EncodedCommand.
        boot_cid = protocol.run_command(
            shell_id, "powershell.exe",
            arguments=["-NoProfile", "-NonInteractive", "-Command", bootstrap]
        )
        boot_out, boot_err, boot_status = protocol.get_command_output(
            shell_id, boot_cid)
        protocol.cleanup_command(shell_id, boot_cid)
        if boot_status != 0:
            print(json.dumps({
                "ok": False, "host": args.host,
                "error": "stage-script failed",
                "status_code": boot_status,
                "stdout": boot_out.decode("utf-8", errors="replace"),
                "stderr": boot_err.decode("utf-8", errors="replace"),
            }))
            return 1
        remote_path = boot_out.decode("utf-8", errors="replace").strip()
        if not remote_path:
            print(json.dumps({
                "ok": False, "host": args.host,
                "error": "stage-script returned no path"
            }))
            return 1

        # Step 2: run the staged file
        run_cid = protocol.run_command(
            shell_id, "powershell.exe",
            arguments=["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                       "-File", remote_path]
        )
        std_out, std_err, status_code = protocol.get_command_output(
            shell_id, run_cid)
        protocol.cleanup_command(shell_id, run_cid)

        # Step 3: best-effort cleanup
        try:
            cleanup_cid = protocol.run_command(
                shell_id, "powershell.exe",
                arguments=["-NoProfile", "-NonInteractive", "-Command",
                           f"Remove-Item -Path '{remote_path}' -Force -ErrorAction SilentlyContinue"]
            )
            protocol.get_command_output(shell_id, cleanup_cid)
            protocol.cleanup_command(shell_id, cleanup_cid)
        except Exception:
            pass  # leftover .ps1 in TEMP isn't fatal
    except Exception as e:
        print(json.dumps({
            "ok": False,
            "host": args.host,
            "error": f"{type(e).__name__}: {e}"
        }))
        return 1
    finally:
        try:
            if shell_id:
                protocol.close_shell(shell_id)
        except Exception:
            pass

    if status_code != 0:
        print(json.dumps({
            "ok": False,
            "host": args.host,
            "error": "PowerShell exited non-zero",
            "status_code": status_code,
            "stdout": std_out.decode("utf-8", errors="replace"),
            "stderr": std_err.decode("utf-8", errors="replace")
        }))
        return 1

    raw = std_out.decode("utf-8", errors="replace").strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({
            "ok": False,
            "host": args.host,
            "error": f"JSON parse error: {e}",
            "raw_stdout": raw[:2000]  # cap to avoid blowing up logs
        }))
        return 1

    # The PS script returns either a dict (single result) or sometimes a list
    # of one dict if PS auto-wraps. Normalize.
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else {}

    # Pass through cleanly to stdout
    print(json.dumps(parsed))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        # Last-resort safety net — should never hit this in normal operation
        print(json.dumps({
            "ok": False,
            "error": "unhandled exception",
            "traceback": traceback.format_exc()
        }), file=sys.stderr)
        sys.exit(1)
