# housekeeping-exo.ps1 -- Exchange Online side of the shared mailbox housekeeping actions.
# Called by housekeeping.js (runExo): one JSON request on stdin, one JSON result line on stdout.
#
#   { action: 'set-type',         identity, type: 'Regular' | 'Shared' }
#   { action: 'set-hidden',       identity, hidden: true | false }              (cloud-only mailboxes)
#   { action: 'remove-delegates', identity, fullAccess: [..], sendAs: [..] }
#   { action: 'add-delegates',    identity, fullAccess: [..], sendAs: [..] }   (revert of remove-delegates)
#   { action: 'remove-mailbox',   identity }                                    (cloud-only; soft delete, 30 days)
#   { action: 'whoami' }                                                        (connect only; proves the cert)
#
# Auth: app-only certificate from the env file in SMBX_EXO_ENV (default /opt/gal-directory/.env: GAL_CLIENT_ID,
# EXO_ORG, EXO_PFX_PASS, optional EXO_PFX_PATH, else exo-app.pfx beside it). The app needs an Exchange role that
# allows these cmdlets (e.g. Exchange Recipient Administrator); without it the cmdlets are missing from the session
# and the error is returned as-is.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Done($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Depth 5 -Compress)); exit 0 }

try { $req = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { Done @{ success = $false; error = 'invalid input' } }
$envFile = if ($env:SMBX_EXO_ENV) { $env:SMBX_EXO_ENV } else { '/opt/gal-directory/.env' }
try {
  foreach ($l in Get-Content $envFile) {
    if ($l -match '^([A-Z_][A-Z0-9_]*)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2].Trim().Trim('"').Trim("'")) }
  }
  $pfx = if ($env:EXO_PFX_PATH) { $env:EXO_PFX_PATH } else { Join-Path (Split-Path $envFile) 'exo-app.pfx' }
  Import-Module ExchangeOnlineManagement *> $null
  Connect-ExchangeOnline -CertificateFilePath $pfx -CertificatePassword (ConvertTo-SecureString $env:EXO_PFX_PASS -AsPlainText -Force) `
    -AppId $env:GAL_CLIENT_ID -Organization $env:EXO_ORG -ShowBanner:$false *> $null
} catch { Done @{ success = $false; error = 'Exchange Online connect failed: ' + $_.Exception.Message } }

function Need($c) { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "$c is not available to this app: it has no Exchange role that allows it (grant e.g. Exchange Recipient Administrator)" } }
$id = "$($req.identity)"
try {
  switch ($req.action) {
    'whoami' { $r = @{ success = $true; message = 'connected'; canWrite = [bool](Get-Command Set-Mailbox -ErrorAction SilentlyContinue) } }
    'set-type' {
      if ($req.type -notin 'Regular', 'Shared') { throw 'type must be Regular or Shared' }
      Need 'Set-Mailbox'
      $before = (Get-EXOMailbox -Identity $id -Properties RecipientTypeDetails).RecipientTypeDetails
      Set-Mailbox -Identity $id -Type $req.type -Confirm:$false
      $r = @{ success = $true; message = "Exchange Online mailbox type set to $($req.type)"; originalState = @{ RecipientTypeDetails = "$before" }; newState = @{ type = $req.type } }
    }
    'set-hidden' {
      Need 'Set-Mailbox'
      $before = (Get-EXOMailbox -Identity $id -Properties HiddenFromAddressListsEnabled).HiddenFromAddressListsEnabled
      Set-Mailbox -Identity $id -HiddenFromAddressListsEnabled ([bool]$req.hidden) -Confirm:$false
      $r = @{ success = $true; message = "HiddenFromAddressListsEnabled set to $([bool]$req.hidden) (was $before)"; originalState = @{ hidden = [bool]$before }; newState = @{ hidden = [bool]$req.hidden } }
    }
    'remove-delegates' {
      Need 'Remove-MailboxPermission'; Need 'Remove-RecipientPermission'
      $okFa = @(); $okSa = @(); $fail = @()
      foreach ($u in @($req.fullAccess)) { if (-not $u) { continue }
        try { Remove-MailboxPermission -Identity $id -User $u -AccessRights FullAccess -InheritanceType All -Confirm:$false; $okFa += $u } catch { $fail += "FullAccess $u : $($_.Exception.Message)" } }
      foreach ($u in @($req.sendAs)) { if (-not $u) { continue }
        try { Remove-RecipientPermission -Identity $id -Trustee $u -AccessRights SendAs -Confirm:$false; $okSa += $u } catch { $fail += "SendAs $u : $($_.Exception.Message)" } }
      $r = @{ success = (($okFa.Count + $okSa.Count) -gt 0 -or $fail.Count -eq 0); message = "Removed $($okFa.Count) Full Access and $($okSa.Count) Send As"
        originalState = @{ fullAccess = $okFa; sendAs = $okSa }; newState = @{ removed = $true }; failures = $fail }
      if ($fail.Count) { $r.message += "; $($fail.Count) failed: " + ($fail -join '; ') }
      if (-not $r.success) { $r.error = $r.message }
    }
    'add-delegates' {
      Need 'Add-MailboxPermission'; Need 'Add-RecipientPermission'
      $fail = @(); $n = 0
      foreach ($u in @($req.fullAccess)) { if (-not $u) { continue }
        try { Add-MailboxPermission -Identity $id -User $u -AccessRights FullAccess -InheritanceType All -AutoMapping:$false -Confirm:$false | Out-Null; $n++ } catch { $fail += "FullAccess $u : $($_.Exception.Message)" } }
      foreach ($u in @($req.sendAs)) { if (-not $u) { continue }
        try { Add-RecipientPermission -Identity $id -Trustee $u -AccessRights SendAs -Confirm:$false | Out-Null; $n++ } catch { $fail += "SendAs $u : $($_.Exception.Message)" } }
      $r = @{ success = ($fail.Count -eq 0); message = "Re-granted $n permission(s) (Full Access without Outlook auto-mapping)" }
      if ($fail.Count) { $r.error = "$($fail.Count) failed: " + ($fail -join '; ') }
    }
    'remove-mailbox' {
      Need 'Remove-Mailbox'
      $mb = Get-EXOMailbox -Identity $id -Properties IsDirSynced
      if ($mb.IsDirSynced) { throw 'mailbox is dirsynced: delete the on-prem AD object instead' }
      Remove-Mailbox -Identity $id -Confirm:$false
      $r = @{ success = $true; message = 'Mailbox deleted (soft-deleted for 30 days; restore from the Exchange admin center)'; originalState = @{ guid = $id }; newState = @{ state = 'soft-deleted' } }
    }
    default { throw "unknown action $($req.action)" }
  }
} catch { $r = @{ success = $false; error = $_.Exception.Message } }
try { Disconnect-ExchangeOnline -Confirm:$false *> $null } catch { }
Done $r
