<#
.SYNOPSIS
  Ограничение корневого сертификата Минцифры списком сайтов (Windows).

.DESCRIPTION
  1. создаёт свой корневой сертификат с nameConstraints (только ваши домены);
  2. переподписывает им корень Минцифры (то же имя и тот же публичный ключ);
  3. проверяет цепочку на ваших сайтах;
  4. удаляет старые версии из хранилищ Windows и устанавливает новые:
       - ваш ограниченный корень   -> «Доверенные корневые центры сертификации»;
       - переподписанный корень    -> «Промежуточные центры сертификации».

  Быстрый старт: git clone <репозиторий>, затем в PowerShell от имени администратора:
      .\scripts\windows\certify.ps1 rzd.ru job.alfabank.ru

  Корневой сертификат Минцифры берётся из папки certs\ репозитория; туда же по умолчанию
  записываются ваши сертификаты (ca.crt, new_root_ca.crt) и список сайтов (sites.txt).

  Работает в Windows PowerShell 5.1 (нужен .NET Framework 4.7.2+, т.е. Windows 10 1803 и новее)
  и в PowerShell 7. OpenSSL не нужен. Приватный ключ вашего корня существует только в памяти
  и на диск не записывается.

  ВАЖНО: файл должен быть сохранён в UTF-8 с BOM, иначе Windows PowerShell 5.1 исказит кириллицу.

.EXAMPLE
  .\scripts\windows\certify.ps1 rzd.ru job.alfabank.ru       # список = ровно эти сайты
  .\scripts\windows\certify.ps1 -Add online.sberbank.ru      # дописать к сохранённому списку
  .\scripts\windows\certify.ps1 -SitesFile my-sites.txt      # список из файла (по одному на строку)
  .\scripts\windows\certify.ps1 -List                        # показать сохранённый список
  .\scripts\windows\certify.ps1 -NoInstall rzd.ru            # только собрать и проверить
  .\scripts\windows\certify.ps1 -Scope CurrentUser rzd.ru    # без прав администратора, только для вас
#>
#Requires -Version 5.1
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
param(
  [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
  [string[]]$Sites,
  [switch]$Add,
  [string]$SitesFile,
  [switch]$List,
  [switch]$NoInstall,
  [switch]$Yes,
  [ValidateSet('LocalMachine', 'CurrentUser')]
  [string]$Scope = 'LocalMachine',
  [switch]$Help
)

$ErrorActionPreference = 'Stop'

$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$RepoDir = Split-Path -Parent (Split-Path -Parent $ScriptRoot)   # scripts\windows -> корень репозитория
$WorkDir   = Join-Path $RepoDir 'certs'    # корень Минцифры лежит здесь же; сюда пишутся и наши сертификаты
$SitesPath = Join-Path $WorkDir 'sites.txt'
$RootCn    = 'Russian Trusted Root CA'
$MyCn      = 'My-Restricted-Root'
$VerifyMax = 5          # сколько сайтов из списка проверять по сети
$OnWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows

function Write-Info([string]$Text) { Write-Host $Text }
function Write-Warn([string]$Text) { Write-Host "ВНИМАНИЕ: $Text" -ForegroundColor Yellow }

function Show-Usage {
  @'
Использование: .\scripts\windows\certify.ps1 [параметры] [сайт ...]

Параметры:
  -Add                добавить сайты к ранее сохранённому списку (по умолчанию список заменяется)
  -SitesFile ФАЙЛ     прочитать сайты из файла (по одному на строку, # — комментарий)
  -List               показать сохранённый список и выйти
  -NoInstall          только собрать и проверить сертификаты, хранилища Windows не менять
  -Scope Область      LocalMachine (по умолчанию, нужен запуск от администратора)
                      или CurrentUser (без администратора, только для вашей учётной записи;
                      Windows покажет окно подтверждения установки корня)
  -Yes                не спрашивать подтверждение установки
  -Verbose            показывать результат проверки по каждому сайту
  -Help               эта справка

Сертификаты и список сайтов (sites.txt) записываются в папку certs\ репозитория.
Для каждого сайта разрешаются и сам домен, и все его поддомены.
Кириллические домены (.рф) можно писать как есть, они преобразуются в punycode.
'@
}

# ---------- DER-кодирование для расширения nameConstraints ----------
function New-Der([byte]$Tag, [byte[]]$Content) {
  $out = New-Object 'System.Collections.Generic.List[byte]'
  $out.Add($Tag)
  $n = $Content.Length
  if ($n -lt 128)     { $out.Add([byte]$n) }
  elseif ($n -lt 256) { $out.Add([byte]0x81); $out.Add([byte]$n) }
  else                { $out.Add([byte]0x82); $out.Add([byte]($n -shr 8)); $out.Add([byte]($n -band 0xFF)) }
  $out.AddRange($Content)
  return , $out.ToArray()
}

function New-NameConstraintsExtension([string[]]$Domains) {
  # В RFC 5280 ограничение «example.ru» покрывает сам домен и все его поддомены.
  $subtrees = New-Object 'System.Collections.Generic.List[byte]'
  foreach ($d in $Domains) {
    $name = New-Der 0x82 ([Text.Encoding]::ASCII.GetBytes($d))   # dNSName [2]
    $subtrees.AddRange((New-Der 0x30 $name))                      # GeneralSubtree
  }
  $permitted = New-Der 0xA0 $subtrees.ToArray()                   # permittedSubtrees [0]
  $seq = New-Der 0x30 $permitted
  return [X509Extension]::new('2.5.29.30', $seq, $true)           # критичное расширение
}

function Get-KeyIdFromSki([X509Extension]$Ski) {
  $raw = $Ski.RawData                                             # OCTET STRING { keyIdentifier }
  $idx = 2
  if ($raw[1] -gt 127) { $idx = 2 + ($raw[1] -band 0x7F) }
  return , [byte[]]($raw[$idx..($raw.Length - 1)])
}

function Get-Ski([X509Certificate2]$Cert) {
  foreach ($e in $Cert.Extensions) { if ($e.Oid.Value -eq '2.5.29.14') { return $e } }
  return $null
}

# ---------- создание сертификатов ----------
function New-RestrictedCa([string[]]$Domains) {
  $rsa = [RSA]::Create(4096)
  $req = [CertificateRequest]::new("CN=$MyCn", $rsa, [HashAlgorithmName]::SHA256, [RSASignaturePadding]::Pkcs1)
  $req.CertificateExtensions.Add([X509BasicConstraintsExtension]::new($true, $true, 5, $true))
  $req.CertificateExtensions.Add([X509KeyUsageExtension]::new([X509KeyUsageFlags]'KeyCertSign, CrlSign, DigitalSignature', $true))
  $req.CertificateExtensions.Add([X509SubjectKeyIdentifierExtension]::new($req.PublicKey, $false))
  $req.CertificateExtensions.Add((New-NameConstraintsExtension $Domains))
  $now = [DateTimeOffset]::UtcNow
  return $req.CreateSelfSigned($now.AddMinutes(-5), $now.AddYears(10))
}

# Копия корня Минцифры (то же имя и тот же публичный ключ), подписанная вашим корнем.
# Ограничения по доменам заданы и в вашем корне, и в этом сертификате: сертификаты внутри цепочки
# проверяются Windows всегда, а ограничения на самом доверенном корне — не во всех проверяющих.
function New-CrossCert([X509Certificate2]$Ca, [X509Certificate2]$Root, [string[]]$Domains) {
  $req = [CertificateRequest]::new($Root.SubjectName, $Root.PublicKey, [HashAlgorithmName]::SHA256)
  $req.CertificateExtensions.Add([X509BasicConstraintsExtension]::new($true, $false, 0, $true))
  $req.CertificateExtensions.Add([X509KeyUsageExtension]::new([X509KeyUsageFlags]'KeyCertSign, CrlSign, DigitalSignature', $true))
  $ski = Get-Ski $Root
  if ($ski) { $req.CertificateExtensions.Add([X509Extension]::new($ski.Oid, $ski.RawData, $false)) }
  else      { $req.CertificateExtensions.Add([X509SubjectKeyIdentifierExtension]::new($req.PublicKey, $false)) }
  $caSki = Get-Ski $Ca
  if ($caSki) {
    $kid = Get-KeyIdFromSki $caSki
    $aki = New-Der 0x30 (New-Der 0x80 $kid)                       # AuthorityKeyIdentifier { [0] keyIdentifier }
    $req.CertificateExtensions.Add([X509Extension]::new('2.5.29.35', $aki, $false))
  }
  $req.CertificateExtensions.Add((New-NameConstraintsExtension $Domains))

  $serial = New-Object byte[] 16
  $rng = [RandomNumberGenerator]::Create(); $rng.GetBytes($serial); $rng.Dispose()
  $serial[0]  = [byte](($serial[0]  -band 0x7F) -bor 0x01)
  $serial[15] = [byte](($serial[15] -band 0x7F) -bor 0x01)

  $notBefore = [DateTimeOffset]$Ca.NotBefore
  $maxAfter  = ([DateTimeOffset]$Ca.NotAfter).AddDays(-1)
  $rootAfter = [DateTimeOffset]$Root.NotAfter
  $notAfter  = if ($rootAfter -lt $maxAfter) { $rootAfter } else { $maxAfter }
  # Подписываем через генератор подписи: этот вариант работает и в .NET Framework 4.7.2, и в .NET 5+.
  $caKey = [RSACertificateExtensions]::GetRSAPrivateKey($Ca)
  $generator = [X509SignatureGenerator]::CreateForRSA($caKey, [RSASignaturePadding]::Pkcs1)
  return $req.Create($Ca.SubjectName, $generator, $notBefore, $notAfter, $serial)
}

function ConvertTo-Pem([byte[]]$Der) {
  $b64 = [Convert]::ToBase64String($Der)
  $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
  return "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----`n"
}

function Save-Pem([string]$Path, [X509Certificate2]$Cert) {
  [IO.File]::WriteAllText($Path, (ConvertTo-Pem $Cert.RawData), [Text.Encoding]::ASCII)
}

# ---------- поиск сертификатов Минцифры ----------
function Read-Cert([string]$Path) {
  try {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text -match '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----') {
      $bytes = [Convert]::FromBase64String(($Matches[1] -replace '\s', ''))
    }
    return [X509Certificate2]::new($bytes)
  } catch { return $null }
}

function Get-CertFiles {
  $dirs = @(Join-Path $RepoDir 'certs') | Where-Object { Test-Path -LiteralPath $_ }
  $files = foreach ($d in $dirs) {
    Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -in '.cer', '.crt', '.pem' -and $_.Name -match 'russian|trusted' -and $_.Name -notmatch 'gost' }
  }
  return @($files | ForEach-Object { $_.FullName } | Select-Object -Unique)
}

# ---------- домены ----------
$DomainRe = '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$'

function ConvertTo-Domain([string]$Raw) {
  $d = $Raw.Trim().ToLowerInvariant()
  $d = $d -replace '^[a-z]+://', ''
  $d = ($d -split '[/?#]')[0]
  $d = ($d -split ':')[0]
  $d = $d -replace '^\*\.', ''
  $d = $d.TrimStart('.')
  if ($d -match '[^\x00-\x7F]') { $d = (New-Object System.Globalization.IdnMapping).GetAscii($d) }
  return $d
}

function Read-SiteLines([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { throw "Не могу прочитать файл: $Path" }
  $out = foreach ($line in (Get-Content -LiteralPath $Path)) {
    $l = ($line -replace '#.*$', '').Trim()
    if ($l) { $l }
  }
  return @($out)
}

# ---------- проверка цепочки ----------
function Get-RemoteChain([string]$HostName, [int]$Port = 443) {
  $tcp = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $tcp.BeginConnect($HostName, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(10000)) { return $null }
    $tcp.EndConnect($iar)
    $script:ServerChain = @()
    $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
      param($sender, $cert, $chain, $errors)
      # копируем сертификаты: после проверки система может освободить исходные объекты
      if ($chain) { $script:ServerChain = @($chain.ChainElements | ForEach-Object { [X509Certificate2]::new($_.Certificate.RawData) }) }
      return $true
    }
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
    try {
      $ssl.AuthenticateAsClient($HostName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
      $leaf = [X509Certificate2]::new($ssl.RemoteCertificate.GetRawCertData())
      return [pscustomobject]@{ Leaf = $leaf; Server = $script:ServerChain }
    } finally { $ssl.Dispose() }
  } catch { return $null } finally { $tcp.Close() }
}

function Test-LeafChain([X509Certificate2]$Leaf, $Extra, [bool]$AllowUnknown) {
  $chain = New-Object X509Chain
  $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::NoCheck
  foreach ($c in $Extra) { if ($c) { [void]$chain.ChainPolicy.ExtraStore.Add($c) } }
  if ($AllowUnknown) { $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::AllowUnknownCertificateAuthority }
  $ok = $chain.Build($Leaf)
  $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() })
  $root = $null
  $n = $chain.ChainElements.Count
  if ($n -gt 0) { $root = $chain.ChainElements[$n - 1].Certificate }
  return [pscustomobject]@{ Ok = $ok; Statuses = $statuses; Root = $root }
}

function Get-CommonName([X509Certificate2]$Cert) {
  if ($Cert -and $Cert.Subject -match 'CN=([^,]+)') { return $Matches[1] }
  if ($Cert) { return $Cert.Subject }
  return '?'
}

# Проверка первых $VerifyMax сайтов списка. $AllowUnknown = $true — проверка до установки (корень ещё не доверенный).
# Без -Quiet печатается сводка; ошибки печатаются всегда, подробности по каждому сайту только с -Verbose.
function Test-Sites([string[]]$Domains, $Local, [bool]$AllowUnknown, [string]$Label, [bool]$Quiet = $false) {
  $sample = @($Domains | Select-Object -First $VerifyMax)
  $ok = 0; $nolink = 0; $bad = 0
  foreach ($d in $sample) {
    $remote = Get-RemoteChain $d
    if (-not $remote) { $nolink++; Write-Verbose "нет связи  $d"; continue }
    # присланные сервером сертификаты (кроме самого сайта и оригинального корня Минцифры) помогают построить цепочку
    $extra = @($Local)
    foreach ($c in $remote.Server) {
      if ($c.Thumbprint -ne $remote.Leaf.Thumbprint -and $c.Subject -notmatch "CN=$RootCn") { $extra += $c }
    }
    $r = Test-LeafChain $remote.Leaf $extra $AllowUnknown
    $rootName = Get-CommonName $r.Root
    if ($r.Ok -and $r.Root -and $r.Root.Subject -match "CN=$MyCn") {
      $ok++; Write-Verbose "OK  $d"
    } elseif ($r.Ok -and $r.Root -and $r.Root.Subject -match 'CN=Russian Trusted') {
      $bad++; Write-Host "  ОШИБКА  ${d}: цепочка заканчивается на '$rootName', в обход ограничения (остался оригинальный корень?)"
    } elseif ($r.Ok) {
      $ok++; Write-Verbose "OK  $d (не сертификат Минцифры, корень: $rootName)"
    } else {
      $bad++
      $st = $r.Statuses -join ', '
      if ($st -match 'NameConstraint') { Write-Host "  ОШИБКА  ${d}: сертификат выдан на имена вне списка (проверьте SAN и добавьте нужный домен)" }
      else { Write-Host "  ОШИБКА  ${d}: $st" }
    }
  }
  if (-not $Quiet) { Write-Host "${Label}: проверено $($sample.Count) из $($Domains.Count): OK $ok, нет связи $nolink, ошибок $bad" }
  return ($bad -gt 0)
}

function Get-ShortPath([string]$Path) {
  $prefix = $RepoDir.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if ($Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $Path.Substring($prefix.Length) }
  return $Path
}

# ---------- хранилища сертификатов ----------
$OldPattern = "CN=$MyCn|CN=$RootCn"

function Open-Store([string]$Name, [string]$Location, [bool]$Write) {
  $s = [X509Store]::new($Name, [StoreLocation]$Location)
  $s.Open($(if ($Write) { [OpenFlags]::ReadWrite } else { [OpenFlags]::ReadOnly }))
  return $s
}

# Ищет прежние версии: свои сертификаты, оригинальный корень Минцифры и «Sub CA» среди доверенных корней
# (Sub CA в доверенных корнях стал бы точкой доверия в обход ограничений).
function Find-OldCerts {
  $found = New-Object System.Collections.ArrayList
  foreach ($loc in 'LocalMachine', 'CurrentUser') {
    foreach ($name in 'Root', 'CA') {
      try { $s = Open-Store $name $loc $false } catch { continue }
      foreach ($c in $s.Certificates) {
        $hit = $c.Subject -match $OldPattern
        if (-not $hit -and $name -eq 'Root' -and $c.Subject -match 'CN=Russian Trusted Sub CA') { $hit = $true }
        if ($hit) { [void]$found.Add([pscustomobject]@{ Location = $loc; Store = $name; Cert = $c }) }
      }
      $s.Close()
    }
  }
  return $found.ToArray()
}

function Test-Admin {
  if (-not $OnWindows) { return $true }
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-ToStore([string]$Name, [string]$Location, [X509Certificate2]$Cert) {
  $s = Open-Store $Name $Location $true
  try { $s.Add($Cert) } finally { $s.Close() }
}

# ---------- основной сценарий ----------
function Main {
  if ($Help) { Show-Usage; return }
  if (-not $OnWindows -and $env:MINCIFRY_ALLOW_NONWINDOWS -ne '1') { throw 'Этот скрипт рассчитан на Windows. Для macOS и Linux используйте scripts/macos/ и scripts/linux/.' }
  if (-not ('System.Security.Cryptography.X509Certificates.CertificateRequest' -as [type])) {
    throw 'Нужен .NET Framework 4.7.2 или новее (Windows 10 версии 1803+) либо PowerShell 7.'
  }

  if ($List) {
    if (Test-Path -LiteralPath $SitesPath) { Get-Content -LiteralPath $SitesPath } else { 'пусто' }
    return
  }

  # --- список сайтов ---
  $raw = @()
  if ($Add -and (Test-Path -LiteralPath $SitesPath)) { $raw += Read-SiteLines $SitesPath }
  if ($SitesFile) { $raw += Read-SiteLines $SitesFile }
  if ($Sites) { $raw += $Sites }
  $domains = @()
  foreach ($r in $raw) {
    if (-not "$r".Trim()) { continue }
    $d = ConvertTo-Domain "$r"
    if ($d -notmatch $DomainRe) { throw "Некорректный домен: '$r'" }
    $domains += $d
  }
  $domains = @($domains | Sort-Object -Unique)
  if ($domains.Count -eq 0) { throw 'Не указано ни одного сайта: передайте домены или файл со списком (-SitesFile), см. -Help.' }

  if (-not $NoInstall -and $Scope -eq 'LocalMachine' -and -not (Test-Admin)) {
    throw "Для установки в хранилище компьютера нужны права администратора: откройте PowerShell «От имени администратора»,`nлибо добавьте параметр -Scope CurrentUser (установка только для вашей учётной записи)."
  }

  # --- корневой сертификат Минцифры ---
  $root = $null; $rootSrc = $null; $subs = @()
  foreach ($f in (Get-CertFiles)) {
    $c = Read-Cert $f
    if (-not $c) { continue }
    if (-not $root -and $c.Subject -match "CN=$RootCn") { $root = $c; $rootSrc = $f }
    elseif ($c.Subject -match 'CN=Russian Trusted Sub CA') { $subs += $c }
  }
  if (-not $root) {
    throw "Не найден корневой сертификат '$RootCn'.`nОжидался файл в папке certs\ репозитория ($(Join-Path $RepoDir 'certs')). Скачайте его на https://www.gosuslugi.ru/crt (.cer, .crt или .pem) и положите туда.`n(Файлы 'Sub CA' и ГОСТ-версии не подходят — нужен именно Root CA.)"
  }

  Write-Host "Корень Минцифры: $(Get-ShortPath $rootSrc)"
  if ($domains.Count -le $VerifyMax) { Write-Host "Сайтов: $($domains.Count) ($($domains -join ', '))" }
  else { Write-Host "Сайтов: $($domains.Count)" }

  # --- сборка (в рабочую папку попадают только ca.crt, new_root_ca.crt и sites.txt; закрытый ключ только в памяти) ---
  Write-Host 'Генерирую сертификаты...'
  $ca = New-RestrictedCa $domains
  $cross = New-CrossCert $ca $root $domains
  $caPublic = [X509Certificate2]::new($ca.RawData)   # без закрытого ключа

  New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
  $caPath = Join-Path $WorkDir 'ca.crt'
  $crossPath = Join-Path $WorkDir 'new_root_ca.crt'
  Save-Pem $caPath $caPublic
  Save-Pem $crossPath $cross
  Set-Content -LiteralPath $SitesPath -Value $domains -Encoding ASCII

  # --- проверка до установки (при установке показываются только ошибки) ---
  $problemBefore = Test-Sites $domains (@($subs) + @($cross, $caPublic)) $true 'Проверка' (-not $NoInstall)

  if ($NoInstall) {
    Write-Host "Сертификаты собраны в $(Get-ShortPath $WorkDir), хранилища Windows не изменены (-NoInstall)."
    return
  }

  # --- установка ---
  $old = @(Find-OldCerts)
  if (-not $Yes) {
    Write-Host ''
    Write-Host "Будет обновлено хранилище сертификатов Windows ($Scope): прежние версии удалены, новые установлены."
    if ($old.Count -gt 0) {
      Write-Host 'Будут удалены (в том числе оригинальный корень и Sub CA Минцифры, иначе они обходят ограничения):'
      foreach ($o in $old) { Write-Host ("  [{0}\{1}] {2}" -f $o.Location, $o.Store, (Get-CommonName $o.Cert)) }
    }
    try { $ans = Read-Host 'Продолжить? [y/N]' }
    catch { throw 'Нужен терминал для подтверждения: добавьте -Yes, чтобы продолжить без вопросов.' }
    if ($ans -notin 'y', 'Y', 'д', 'Д') { Write-Host "Отменено, хранилища не тронуты. Сертификаты лежат в $(Get-ShortPath $WorkDir)."; return }
  }

  foreach ($o in $old) {
    try {
      $s = Open-Store $o.Store $o.Location $true
      try { $s.Remove($o.Cert) } finally { $s.Close() }
    } catch {
      Write-Warn ("Не удалось удалить из [{0}\{1}]: {2}. Удалите вручную (certmgr.msc / certlm.msc)." -f $o.Location, $o.Store, $o.Cert.Subject)
    }
  }

  Add-ToStore 'Root' $Scope $caPublic
  Add-ToStore 'CA' $Scope $cross

  [void](Test-Sites $domains $subs $false 'Проверка после установки')

  Write-Host 'Готово. Перезапустите браузер.'
  Write-Host "Firefox использует своё хранилище: импортируйте в него вручную $(Get-ShortPath $caPath) и new_root_ca.crt (см. README)."
}

# При запуске скрипта выполняем Main; при подключении через «. скрипт» (для тестов) только определяем функции.
if ($MyInvocation.InvocationName -ne '.') {
  try { Main } catch { Write-Host "ОШИБКА: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}
