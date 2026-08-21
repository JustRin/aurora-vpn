# Собрать установщик Aurora VPN.
#
# Приложение и ядро должны быть уже собраны: скрипт только раскладывает готовые
# файлы во временную папку и зовёт makensis. Версия берётся из package.json —
# единственного места, где она живёт.
#
#   powershell -ExecutionPolicy Bypass -File installer\build.ps1
[CmdletBinding()]
param(
    # Куда положить готовый установщик. Пусто — рядом со сборкой.
    [string]$OutDir
)

$ErrorActionPreference = "Stop"
# $PSScriptRoot в блоке param ещё не заполнен, поэтому пути считаются здесь.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $here "..\..")
if (-not $OutDir) { $OutDir = Join-Path $here "..\target\installer" }
$crate = Join-Path $root "spike-slint"

$version = (Get-Content (Join-Path $root "package.json") -Raw | ConvertFrom-Json).version
Write-Host "версия: $version"

# NSIS кладёт к себе CLI Tauri; своей установки в системе может и не быть.
$makensis = @(
    "$env:LOCALAPPDATA\tauri\NSIS\makensis.exe",
    "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
    "$env:ProgramFiles\NSIS\makensis.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $makensis) { throw "makensis.exe не найден" }

$app = Join-Path $crate "target\release\aurora-vpn.exe"
if (-not (Test-Path $app)) { throw "нет $app — сначала cargo build --release" }

$binaries = Join-Path $root "src-tauri\binaries"
$triple = "x86_64-pc-windows-msvc"

# Файлы собираются в отдельной папке: в .nsi тогда одно имя на файл, без
# суффиксов целевой тройки, под которыми ядро лежит в дереве сборки.
$stage = Join-Path $crate "target\installer-stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Copy-Item $app (Join-Path $stage "aurora-vpn.exe")
Copy-Item (Join-Path $binaries "sing-box-$triple.exe") (Join-Path $stage "sing-box.exe")
Copy-Item (Join-Path $binaries "xray-$triple.exe") (Join-Path $stage "xray.exe")

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
# Имя как у прежних релизов: по нему встроенное обновление узнаёт свой файл
# среди вложений релиза (pick_installer_url в api.rs).
$outFile = Join-Path (Resolve-Path $OutDir) "AuroraVPN-$version-windows-x64-setup.exe"

& $makensis `
    "/DVERSION=$version" `
    "/DSOURCE=$stage" `
    "/DOUTFILE=$outFile" `
    "/DICON=$(Join-Path $root 'src-tauri\icons\icon.ico')" `
    (Join-Path $here "aurora-vpn.nsi")
if ($LASTEXITCODE -ne 0) { throw "makensis вернул $LASTEXITCODE" }

Remove-Item $stage -Recurse -Force
$size = [math]::Round((Get-Item $outFile).Length / 1MB, 1)
Write-Host "готово: $outFile ($size МБ)"
