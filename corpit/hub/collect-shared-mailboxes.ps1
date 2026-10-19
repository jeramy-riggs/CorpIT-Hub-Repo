# collect-shared-mailboxes.ps1 -- READ-ONLY Exchange Online snapshot of every shared mailbox.
# Run by collect-shared-mailboxes.js (never on its own in production); writes one JSON file and nothing else.
#
#   pwsh -NoProfile -File collect-shared-mailboxes.ps1 -Out <file> [-TraceDays 30] [-EnvFile /opt/gal-directory/.env] [-Limit N]
#
# Auth: the GAL app's certificate (same connect as /opt/gal-directory/gal-add-members.ps1). Only Get-* cmdlets are used.
# Per mailbox: size/items/LastUserActionTime, newest received (Inbox, Archive and user folders) and newest sent
# (Sent Items), Full Access and Send As delegates. Newest received/sent also take the newest message-trace time. Then message trace counts (received / sent, unique messages)
# for the last -TraceDays days, batched by address. Get-MessageTraceV2 takes at most 10 days per query and is
# throttled at about 100 queries per 5 minutes, so trace calls are paced.
# Exit codes: 0 ok (file written) | 1 cannot connect / enumerate (no file written).
param(
  [Parameter(Mandatory = $true)][string]$Out,
  [int]$TraceDays = 30,
  [string]$EnvFile = '/opt/gal-directory/.env',
  [int]$Limit = 0
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Log($m) { [Console]::Error.WriteLine(('[{0:HH:mm:ss}] {1}' -f (Get-Date).ToUniversalTime(), $m)) }
function Iso($d) { if ($null -eq $d -or $d -eq '') { return $null }; try { return ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null } }
function MaxDate($a, $b) { if ($null -eq $a) { return $b }; if ($null -eq $b) { return $a }; if ([datetime]$a -gt [datetime]$b) { return $a }; return $b }

if ($TraceDays -lt 0 -or $TraceDays -gt 90) { Log 'TraceDays must be 0..90'; exit 1 }
foreach ($l in Get-Content $EnvFile) {
  if ($l -match '^([A-Z_][A-Z0-9_]*)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2].Trim().Trim('"').Trim("'")) }
}
$pfx = if ($env:EXO_PFX_PATH) { $env:EXO_PFX_PATH } else { Join-Path (Split-Path $EnvFile) 'exo-app.pfx' }

try {
  Import-Module ExchangeOnlineManagement
  Connect-ExchangeOnline -CertificateFilePath $pfx -CertificatePassword (ConvertTo-SecureString $env:EXO_PFX_PASS -AsPlainText -Force) `
    -AppId $env:GAL_CLIENT_ID -Organization $env:EXO_ORG -ShowBanner:$false
  $boxes = @(Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited `
    -Properties HiddenFromAddressListsEnabled, IsDirSynced, WhenCreated, ExternalDirectoryObjectId, UserPrincipalName, Alias)
} catch { Log ('connect/enumerate failed: ' + $_.Exception.Message); exit 1 }
if ($Limit -gt 0) { $boxes = @($boxes | Select-Object -First $Limit) }
$started = Iso (Get-Date)
Log ("shared mailboxes: {0}" -f $boxes.Count)

$rows = New-Object System.Collections.Generic.List[object]
$sw = [Diagnostics.Stopwatch]::StartNew(); $i = 0; $errs = 0
$recvFolders = @('Inbox', 'Archive', 'User Created')
foreach ($b in $boxes) {
  $i++
  $id = $b.ExternalDirectoryObjectId
  $r = [ordered]@{
    mailbox_guid = $id; display_name = $b.DisplayName; primary_smtp = "$($b.PrimarySmtpAddress)".ToLower(); upn = $b.UserPrincipalName
    alias = $b.Alias; is_dirsynced = [bool]$b.IsDirSynced; hidden_gal = [bool]$b.HiddenFromAddressListsEnabled; when_created = (Iso $b.WhenCreated)
    item_count = $null; size_bytes = $null; last_user_action = $null; last_received = $null; last_sent = $null
    full_access = @(); send_as = @(); error = $null
  }
  $fail = @()
  try {
    $st = Get-EXOMailboxStatistics -Identity $id -Properties LastUserActionTime
    $r.item_count = [int]$st.ItemCount
    if ("$($st.TotalItemSize)" -match '\(([\d,]+) bytes\)') { $r.size_bytes = [int64]($matches[1] -replace ',', '') }
    $r.last_user_action = Iso $st.LastUserActionTime
  } catch { $fail += 'stats: ' + $_.Exception.Message }
  try {
    $newestIn = $null; $newestOut = $null
    foreach ($f in @(Get-EXOMailboxFolderStatistics -Identity $id -IncludeOldestAndNewestItems)) {
      $d = Iso $f.NewestItemReceivedDate
      if ($f.FolderType -eq 'SentItems') { $newestOut = MaxDate $newestOut $d }
      elseif ($recvFolders -contains $f.FolderType) { $newestIn = MaxDate $newestIn $d }
    }
    $r.last_received = $newestIn; $r.last_sent = $newestOut
  } catch { $fail += 'folders: ' + $_.Exception.Message }
  try {
    $r.full_access = @(Get-EXOMailboxPermission -Identity $id | Where-Object {
        -not $_.IsInherited -and -not $_.Deny -and "$($_.AccessRights)" -match 'FullAccess' -and "$($_.User)" -notmatch '^(NT AUTHORITY\\|S-1-5-)' } |
      ForEach-Object { "$($_.User)" } | Sort-Object -Unique)
  } catch { $fail += 'fullaccess: ' + $_.Exception.Message }
  try {
    $r.send_as = @(Get-EXORecipientPermission -Identity $id | Where-Object {
        "$($_.AccessRights)" -match 'SendAs' -and "$($_.AccessControlType)" -eq 'Allow' -and "$($_.Trustee)" -notmatch '^(NT AUTHORITY\\|S-1-5-)' } |
      ForEach-Object { "$($_.Trustee)" } | Sort-Object -Unique)
  } catch { $fail += 'sendas: ' + $_.Exception.Message }
  if ($fail.Count) { $errs++; $r.error = ($fail -join ' | ').Substring(0, [Math]::Min(480, ($fail -join ' | ').Length)) }
  $rows.Add($r)
  if ($i % 25 -eq 0 -or $i -eq $boxes.Count) { Log ("mailboxes {0}/{1}  errors {2}  {3}s" -f $i, $boxes.Count, $errs, [int]$sw.Elapsed.TotalSeconds) }
}

# Message trace: unique message counts and newest message time per address over the last $TraceDays days, in <=10-day
# windows. The newest time also catches Send As mail, which lands in the sender's own Sent Items, not the shared mailbox's.
$recv = @{}; $sent = @{}; $lastR = @{}; $lastS = @{}; $traceErr = $null
if ($TraceDays -gt 0) {
  $addrs = @($rows | ForEach-Object { $_.primary_smtp } | Where-Object { $_ })
  $now = (Get-Date).ToUniversalTime(); $calls = 0
  $windows = @(); for ($s = $TraceDays; $s -gt 0; $s -= 10) { $windows += , @($now.AddDays(-$s), $now.AddDays(-[Math]::Max(0, $s - 10))) }
  try {
    foreach ($dir in 'recv', 'sent') {
      $seen = @{}
      for ($k = 0; $k -lt $addrs.Count; $k += 50) {
        $batch = $addrs[$k..([Math]::Min($k + 49, $addrs.Count - 1))]
        foreach ($w in $windows) {
          $end = $w[1]; $startAt = $null
          while ($true) {
            $p = @{ StartDate = $w[0]; EndDate = $end; ResultSize = 5000; WarningAction = 'SilentlyContinue' }
            if ($dir -eq 'recv') { $p.RecipientAddress = $batch } else { $p.SenderAddress = $batch }
            if ($startAt) { $p.StartingRecipientAddress = $startAt }
            Start-Sleep -Milliseconds 3100; $calls++
            $res = @(Get-MessageTraceV2 @p)
            foreach ($m in $res) {
              $a = if ($dir -eq 'recv') { "$($m.RecipientAddress)".ToLower() } else { "$($m.SenderAddress)".ToLower() }
              $key = $a + '|' + $m.MessageId
              if (-not $seen.ContainsKey($key)) { $seen[$key] = 1; $t = if ($dir -eq 'recv') { $recv } else { $sent }; $t[$a] = 1 + [int]$t[$a] }
              $lt = if ($dir -eq 'recv') { $lastR } else { $lastS }; $lt[$a] = MaxDate $lt[$a] (Iso $m.Received)
            }
            if ($res.Count -lt 5000) { break }
            $last = $res[-1]; $end = $last.Received; $startAt = $last.RecipientAddress
          }
        }
      }
      Log ("trace {0} done ({1} calls)" -f $dir, $calls)
    }
  } catch { $traceErr = 'message trace: ' + $_.Exception.Message; Log $traceErr }
}
foreach ($r in $rows) {
  if ($TraceDays -gt 0 -and -not $traceErr) {
    $r.recv_count = [int]$recv[$r.primary_smtp]; $r.sent_count = [int]$sent[$r.primary_smtp]
    $r.last_received = MaxDate $r.last_received $lastR[$r.primary_smtp]; $r.last_sent = MaxDate $r.last_sent $lastS[$r.primary_smtp]
  }
  else { $r.recv_count = $null; $r.sent_count = $null }
}

$doc = [ordered]@{ started = $started; finished = (Iso (Get-Date)); trace_days = $(if ($traceErr) { $null } else { $TraceDays }); trace_error = $traceErr
  count = $rows.Count; errors = $errs; mailboxes = $rows }
$tmp = $Out + '.part'
$doc | ConvertTo-Json -Depth 6 -Compress | Set-Content -Path $tmp -Encoding utf8NoBOM
Move-Item -Force $tmp $Out
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Log ("wrote {0} mailboxes to {1} in {2}s" -f $rows.Count, $Out, [int]$sw.Elapsed.TotalSeconds)
exit 0
