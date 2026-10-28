# Offline test for Windows (run it in Windows PowerShell 5.1 AND in PowerShell 7).
# It changes the MACHINE trust store, so it runs only in CI (needs an elevated session).
# The script is run from a copy of the repository layout (scripts\, certs\) that contains the
# FAKE root, exactly like a user would run it after "git clone".
#   0. no terminal and no -Yes                        -> certify refuses to install; removed options are rejected
#   1. before: the fake Mincifry root is not trusted  -> connections fail
#   2. control: install the UNRESTRICTED root         -> good AND evil succeed
#   3. a list of sites                                -> good OK, evil rejected; only 3 files are generated in certs\
#   4. another list                                   -> the old list is replaced; certs\ holds the same files
#   5. -Add -SitesFile FILE                           -> lists are merged
#   6. -List                                          -> prints the saved list
#   7. uninstall: no terminal and no flags            -> refuses
#   8. uninstall -Certs                               -> certificates are gone, project stays
#   9. uninstall -All from inside the project         -> refuses, nothing is deleted
#  10. uninstall -All from the parent directory       -> project folder (with the script itself) is deleted
$ErrorActionPreference = 'Continue'
if ($env:CI -ne 'true') { Write-Host 'This test modifies the machine trust store and runs only in CI (CI=true).'; exit 2 }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$work = Join-Path $base ('mc-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$pki = Join-Path $work 'pki'; $tmpRepo = Join-Path $work 'repo'
$tmpScript = Join-Path $tmpRepo 'scripts\windows\certify.ps1'
$tmpUninstall = Join-Path $tmpRepo 'scripts\windows\uninstall.ps1'

$gitBash = 'C:\Program Files\Git\bin\bash.exe'
$openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
$psExe = (Get-Process -Id $PID).Path
$fails = 0
$servers = @()
$script:LastOut = ''

function Pass([string]$Text) { Write-Host "  PASS  $Text" }
function Fail([string]$Text) { Write-Host "  FAIL  $Text"; $script:fails++ }
function Invoke-Tls([string]$Name, [int]$Port) {
  & $curl -sS -o NUL --max-time 15 --ssl-no-revoke --resolve "${Name}:${Port}:127.0.0.1" "https://${Name}:${Port}/" 2>$null
  return $LASTEXITCODE
}
function Test-ServerAlive([int]$Port) {
  & $curl -sk -o NUL --max-time 5 "https://127.0.0.1:${Port}/" 2>$null
  return ($LASTEXITCODE -eq 0)
}
function Expect-Ok([string]$Label, [string]$Name, [int]$Port) {
  $rc = Invoke-Tls $Name $Port
  if ($rc -eq 0) { Pass "${Label}: $Name accepted" } else { Fail "${Label}: $Name rejected (curl exit $rc), expected accepted" }
}
function Expect-Rejected([string]$Label, [string]$Name, [int]$Port) {
  $rc = Invoke-Tls $Name $Port
  if ($rc -eq 0) { Fail "${Label}: $Name accepted, expected rejected" }
  elseif ($rc -in 6, 7, 28) { Fail "${Label}: $Name network problem (curl exit $rc)" }
  elseif (-not (Test-ServerAlive $Port)) { Fail "${Label}: $Name test server is not responding" }
  else { Pass "${Label}: $Name rejected (curl exit $rc)" }
}
function Expect-Files([string]$Dir, [string]$Expected) {
  $got = (Get-ChildItem -LiteralPath $Dir -Name | Sort-Object) -join ' '
  $want = ($Expected -split ' ' | Sort-Object) -join ' '
  if ($got -eq $want) { Pass "files in $(Split-Path -Leaf $Dir): $got" } else { Fail "files in $(Split-Path -Leaf $Dir): '$got', expected '$want'" }
}
function Add-ControlRoot([string]$CerPath) {
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
  $store.Open('ReadWrite')
  $store.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CerPath)))
  $store.Close()
}
function Invoke-Mincifry([string[]]$ScriptArgs) {
  $script:LastOut = & $psExe -NoProfile -ExecutionPolicy Bypass -File $tmpScript -Yes @ScriptArgs 2>&1 | Out-String
  return $LASTEXITCODE
}
function Run-Checked([string[]]$ScriptArgs) {   # runs the script, checks the exit code and that the output is short
  $rc = Invoke-Mincifry $ScriptArgs
  if ($rc -ne 0) { Fail "script exited with ${rc}: $($script:LastOut)" }
  $n = @($script:LastOut -split "`r?`n" | Where-Object { $_.Trim() }).Count
  if ($n -le 12) { Pass "concise output ($n lines)" } else { Fail "output is too long ($n lines): $($script:LastOut)" }
}

Write-Host '== setup: fake PKI, repository copy and local TLS servers'
New-Item -ItemType Directory -Force -Path $work | Out-Null
& $gitBash ((Join-Path $repo 'tests/fake-pki.sh') -replace '\\', '/') ($pki -replace '\\', '/') | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL: cannot generate the fake PKI'; exit 1 }
New-Item -ItemType Directory -Force -Path (Join-Path $tmpRepo 'certs') | Out-Null
Copy-Item (Join-Path $repo 'scripts') (Join-Path $tmpRepo 'scripts') -Recurse
Copy-Item (Join-Path $pki 'root.cer') (Join-Path $tmpRepo 'certs\russian_trusted_root_ca.cer')
Copy-Item (Join-Path $pki 'sub.cer') (Join-Path $tmpRepo 'certs\russian_trusted_sub_ca.cer')
$sitesList = Join-Path $work 'sites-list.txt'
Set-Content -LiteralPath $sitesList -Value @('# sites list (test)', 'mincifry-ci.test') -Encoding ASCII

foreach ($spec in @(@('good', 9443), @('sub2', 9444), @('evil', 9445))) {
  $n = $spec[0]; $p = $spec[1]
  $argLine = "s_server -accept $p -cert `"$pki\$n.pem`" -key `"$pki\$n.key`" -cert_chain `"$pki\sub.pem`" -www -quiet"
  $servers += Start-Process -FilePath $openssl -ArgumentList $argLine -PassThru -WindowStyle Hidden
}
$ready = $false
for ($i = 0; $i -lt 30 -and -not $ready; $i++) {
  Start-Sleep -Milliseconds 500
  $ready = (Test-ServerAlive 9443) -and (Test-ServerAlive 9444) -and (Test-ServerAlive 9445)
}
if (-not $ready) { Write-Host 'FAIL: local TLS servers did not start'; $servers | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }; exit 1 }

try {
  Write-Host '== 0. no terminal and no -Yes: must refuse to install'
  & $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $tmpScript mincifry-ci.test *> $null
  if ($LASTEXITCODE -ne 0) { Pass "refused without a terminal (exit $LASTEXITCODE)" } else { Fail 'expected a refusal without a terminal' }
  & $psExe -NoProfile -ExecutionPolicy Bypass -File $tmpScript -Yes -WorkDir (Join-Path $work 'x') mincifry-ci.test *> $null
  $rcWd = $LASTEXITCODE
  & $psExe -NoProfile -ExecutionPolicy Bypass -File $tmpScript -Yes -RootCa (Join-Path $pki 'root.cer') mincifry-ci.test *> $null
  $rcRc = $LASTEXITCODE
  if ($rcWd -ne 0 -and $rcRc -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $work 'x'))) { Pass 'removed options (-WorkDir, -RootCa) are rejected' } else { Fail "removed options still accepted (exit $rcWd, $rcRc)" }

  Write-Host '== 1. before: nothing is trusted'
  Expect-Rejected 'before' 'good.mincifry-ci.test' 9443

  Write-Host '== 2. control: unrestricted root is installed (this is the problem we solve)'
  Add-ControlRoot (Join-Path $pki 'root.cer')
  Expect-Ok 'control' 'good.mincifry-ci.test' 9443
  Expect-Ok 'control' 'evil.not-listed.test' 9445

  Write-Host '== 3. a list of sites'
  Run-Checked @('mincifry-ci.test')
  Expect-Ok       'default' 'good.mincifry-ci.test' 9443
  Expect-Ok       'default' 'www.good.mincifry-ci.test' 9444
  Expect-Rejected 'default' 'evil.not-listed.test' 9445
  Expect-Files (Join-Path $tmpRepo 'certs') 'ca.crt new_root_ca.crt russian_trusted_root_ca.cer russian_trusted_sub_ca.cer sites.txt'

  Write-Host '== 4. another list: unrelated.test (old list must be replaced)'
  Run-Checked @('unrelated.test')
  Expect-Rejected 'replaced' 'good.mincifry-ci.test' 9443
  Expect-Rejected 'replaced' 'evil.not-listed.test' 9445
  Expect-Files (Join-Path $tmpRepo 'certs') 'ca.crt new_root_ca.crt russian_trusted_root_ca.cer russian_trusted_sub_ca.cer sites.txt'

  Write-Host '== 5. -Add -SitesFile FILE: lists are merged'
  Run-Checked @('-Add', '-SitesFile', $sitesList)
  Expect-Ok       'merged' 'good.mincifry-ci.test' 9443
  Expect-Rejected 'merged' 'evil.not-listed.test' 9445

  Write-Host '== 6. -List'
  $listed = @(& $psExe -NoProfile -ExecutionPolicy Bypass -File $tmpScript -List).Count
  if ($listed -eq 2) { Pass '-List prints 2 saved sites' } else { Fail "-List printed $listed lines, expected 2" }

  Write-Host '== 7. uninstall without flags and without a terminal: must refuse'
  & $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $tmpUninstall *> $null
  if ($LASTEXITCODE -ne 0) { Pass "refused without a terminal (exit $LASTEXITCODE)" } else { Fail 'expected a refusal without a terminal' }

  Write-Host '== 8. uninstall -Certs'
  $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $tmpUninstall -Certs -Yes 2>&1 | Out-String
  $rc = $LASTEXITCODE
  $n = @($out -split "`r?`n" | Where-Object { $_.Trim() }).Count
  if ($rc -eq 0 -and $n -le 6) { Pass "certificates removed, concise output ($n lines)" } else { Fail "uninstall -Certs: exit $rc, $n lines: $out" }
  Expect-Rejected 'uninstalled' 'good.mincifry-ci.test' 9443
  if (Test-Path -LiteralPath (Join-Path $tmpRepo 'scripts')) { Pass 'project folder is still there' } else { Fail 'project folder was removed by -Certs' }

  Write-Host '== 9. uninstall -All from inside the project: must refuse'
  Push-Location $tmpRepo
  & $psExe -NoProfile -ExecutionPolicy Bypass -File $tmpUninstall -All -Yes *> $null
  $rc = $LASTEXITCODE
  Pop-Location
  if ($rc -ne 0 -and (Test-Path -LiteralPath (Join-Path $tmpRepo 'scripts'))) { Pass "refused inside the project (exit $rc), nothing deleted" } else { Fail "expected a refusal inside the project (exit $rc)" }

  Write-Host '== 10. uninstall -All from the parent directory'
  Push-Location $work
  & $psExe -NoProfile -ExecutionPolicy Bypass -File $tmpUninstall -All -Yes *> $null
  $rc = $LASTEXITCODE
  Pop-Location
  if ($rc -eq 0 -and -not (Test-Path -LiteralPath $tmpRepo)) { Pass 'project folder deleted together with the script' } else { Fail "project folder was not deleted (exit $rc)" }
}
finally {
  $servers | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
if ($fails -eq 0) { Write-Host 'ALL TESTS PASSED' } else { Write-Host "$fails CHECK(S) FAILED"; exit 1 }
