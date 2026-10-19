# =============================================================================
# gal-add-members.ps1 - unattended member add for the Directory Sync console.
#
# Reads a JSON array of email addresses on stdin, connects to Exchange Online
# app-only (certificate), adds each to gal-sync-targets, prints one JSON object
# per address on stdout:  {"email":"...","result":"added|already|failed","detail":"..."}
#
# Auth: the NRPI Directory Sync app registration with Exchange.ManageAsApp and
# the Exchange Recipient Administrator role. Certificate: /opt/gal-directory/
# exo-app.pfx, password in .env (EXO_PFX_PASS). Requires those one-time grants;
# until they exist, every row returns failed with the auth error verbatim.
# =============================================================================
$ErrorActionPreference = 'Stop'

# .env into process env (KEY=value lines only, values taken literally)
Get-Content /opt/gal-directory/.env | ForEach-Object {
  if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
    if (-not (Test-Path ("Env:" + $Matches[1]))) {
      Set-Item -Path ("Env:" + $Matches[1]) -Value $Matches[2]
    }
  }
}

$addresses = [Console]::In.ReadToEnd() | ConvertFrom-Json
if (-not $addresses -or $addresses.Count -eq 0) { Write-Output '[]'; exit 0 }

$results = @()
try {
  Connect-ExchangeOnline `
    -CertificateFilePath /opt/gal-directory/exo-app.pfx `
    -CertificatePassword (ConvertTo-SecureString -String $env:EXO_PFX_PASS -AsPlainText -Force) `
    -AppId $env:GAL_CLIENT_ID `
    -Organization $env:EXO_ORG `
    -ShowBanner:$false
} catch {
  $msg = $_.Exception.Message
  foreach ($a in $addresses) {
    $results += @{ email = $a; result = 'failed'; detail = ('connect: ' + $msg.Substring(0, [Math]::Min(200, $msg.Length))) }
  }
  $results | ConvertTo-Json -AsArray
  exit 1
}

foreach ($a in $addresses) {
  try {
    Add-DistributionGroupMember -Identity gal-sync-targets -Member $a -BypassSecurityGroupManagerCheck
    $results += @{ email = $a; result = 'added'; detail = '' }
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match 'already a member') {
      $results += @{ email = $a; result = 'already'; detail = '' }
    } else {
      $results += @{ email = $a; result = 'failed'; detail = $msg.Substring(0, [Math]::Min(200, $msg.Length)) }
    }
  }
}

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
$results | ConvertTo-Json -AsArray
