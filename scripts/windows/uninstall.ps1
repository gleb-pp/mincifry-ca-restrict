<#
.SYNOPSIS
  Удаление сертификатов (и, по желанию, всего проекта), Windows.

.DESCRIPTION
  Без параметров скрипт спрашивает, что удалить: только сертификаты из системы или весь проект
  (сертификаты и папку репозитория вместе с этим скриптом), а затем просит подтверждение.
  Для удаления всего проекта запускайте скрипт из папки выше репозитория.
  Для сертификатов в хранилище компьютера нужен запуск от администратора.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File mincifry-ca-restrict\scripts\windows\uninstall.ps1
  powershell -ExecutionPolicy Bypass -File ...\uninstall.ps1 -Certs -Yes     # без вопросов: только сертификаты
#>
#Requires -Version 5.1
using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
param(
  [switch]$Certs,
  [switch]$All,
  [switch]$Yes,
  [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$RepoDir = Split-Path -Parent (Split-Path -Parent $ScriptRoot)   # scripts\windows -> корень репозитория
$OnWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
$OurPattern = 'CN=My-Restricted-Root|CN=Russian Trusted Root CA'   # наш корень и переподписанный корень Минцифры

function Show-Usage {
  @'
Использование: powershell -File <папка проекта>\scripts\windows\uninstall.ps1 [параметры]

Без параметров скрипт спросит, что удалить.
  -Certs   удалить только сертификаты из системы
  -All     удалить всё: сертификаты и папку проекта целиком
  -Yes     не спрашивать подтверждение
  -Help    эта справка

Для -All запускайте скрипт из папки выше проекта (не изнутри него).
'@
}

function Open-Store([string]$Name, [string]$Location, [bool]$Write) {
  $s = [X509Store]::new($Name, [StoreLocation]$Location)
  $s.Open($(if ($Write) { [OpenFlags]::ReadWrite } else { [OpenFlags]::ReadOnly }))
  return $s
}

function Find-OurCerts {
  $found = New-Object System.Collections.ArrayList
  foreach ($loc in 'LocalMachine', 'CurrentUser') {
    foreach ($name in 'Root', 'CA') {
      try { $s = Open-Store $name $loc $false } catch { continue }
      foreach ($c in $s.Certificates) {
        if ($c.Subject -match $OurPattern) { [void]$found.Add([pscustomobject]@{ Location = $loc; Store = $name; Cert = $c }) }
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

# Перед удалением папки проверяем, что это наш проект и что мы не стоим внутри неё
function Assert-ProjectDir {
  if (-not ((Test-Path -LiteralPath (Join-Path $RepoDir 'scripts\common.sh')) -and (Test-Path -LiteralPath (Join-Path $RepoDir 'certs')))) {
    throw "Папка $RepoDir не похожа на проект, удалять не буду."
  }
  $full = [IO.Path]::GetFullPath($RepoDir).TrimEnd('\', '/')
  if ($full -eq [IO.Path]::GetPathRoot($full).TrimEnd('\', '/') -or $full -eq $HOME.TrimEnd('\', '/')) { throw "Отказываюсь удалять $full." }
  $here = [IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if ($here.StartsWith($full + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Вы находитесь внутри папки проекта. Перейдите выше (cd ..) и запустите скрипт снова.'
  }
}

function Main {
  if ($Help) { Show-Usage; return }
  if (-not $OnWindows -and $env:MINCIFRY_ALLOW_NONWINDOWS -ne '1') { throw 'Этот скрипт рассчитан на Windows. Для macOS и Linux используйте scripts/macos/ и scripts/linux/.' }
  if ($Certs -and $All) { throw 'Укажите что-то одно: -Certs или -All.' }

  $mode = if ($All) { 'all' } elseif ($Certs) { 'certs' } else { '' }
  if (-not $mode) {
    Write-Host 'Что удалить?'
    Write-Host '  1) сертификаты из системы'
    Write-Host "  2) весь проект: сертификаты и папку $RepoDir"
    try { $choice = Read-Host 'Выбор [1/2]' } catch { throw 'Нужен терминал или параметр -Certs / -All (см. -Help).' }
    switch ($choice) { '1' { $mode = 'certs' } '2' { $mode = 'all' } default { Write-Host 'Отменено.'; return } }
  }
  if ($mode -eq 'all') { Assert-ProjectDir }

  if (-not $Yes) {
    if ($mode -eq 'all') { Write-Host "Будут удалены сертификаты из системы и папка $RepoDir (вместе с этим скриптом)." }
    else { Write-Host 'Будут удалены сертификаты из системы.' }
    try { $ans = Read-Host 'Вы уверены? [y/N]' } catch { throw 'Нужен терминал для подтверждения: добавьте -Yes.' }
    if ($ans -notin 'y', 'Y', 'д', 'Д') { Write-Host 'Отменено.'; return }
  }

  $found = @(Find-OurCerts)
  $removed = 0; $skipped = 0
  foreach ($o in $found) {
    if ($o.Location -eq 'LocalMachine' -and -not (Test-Admin)) { $skipped++; continue }
    try {
      $s = Open-Store $o.Store $o.Location $true
      try { $s.Remove($o.Cert) } finally { $s.Close() }
      $removed++
    } catch { $skipped++ }
  }
  Write-Host "Удалено сертификатов: $removed."
  if ($skipped -gt 0) { Write-Host "Не удалось удалить: $skipped (для хранилища компьютера запустите PowerShell от имени администратора)." -ForegroundColor Yellow }
  Write-Host 'Если вы импортировали сертификаты в Firefox вручную, удалите их и там.'

  if ($mode -eq 'all') {
    Remove-Item -LiteralPath $RepoDir -Recurse -Force
    Write-Host "Папка проекта удалена: $RepoDir"
  }
}

# При запуске скрипта выполняем Main; при подключении через «. скрипт» (для тестов) только определяем функции.
if ($MyInvocation.InvocationName -ne '.') {
  try { Main } catch { Write-Host "ОШИБКА: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}