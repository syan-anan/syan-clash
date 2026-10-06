# Builds the Windows client: a single syan-clash.exe with no console window.
#
# -H=windowsgui marks the binary as a GUI application, which is what stops
# Windows from opening a console window for it. Everything the program prints
# goes to syan-clash-startup.log beside the executable instead.
#
# Brand assets live in cmd\desktop\rsrc_windows_amd64.syso (icon + DPI manifest);
# the Go linker picks that file up automatically, so the exe carries its icon
# with no extra file needed at runtime. The .ico is still copied beside the exe
# because the notification area loads the exact metric it wants from it.
#
# Every path is derived from this script's own location, so the checkout can sit
# anywhere and the output lands next to the sources it was built from.
param(
    [string]$Out = '',
    [string]$Version = '0.1.2',
    [string]$Commit = 'local',
    [switch]$Console
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not $Out) { $Out = Join-Path $root 'syan-clash.exe' }

if (-not (Test-Path (Join-Path $root 'cmd\desktop\rsrc_windows_amd64.syso'))) {
    Write-Warning 'rsrc_windows_amd64.syso is missing - building without brand icon/manifest'
}

# The build stamp is what turns "a bug in syan-clash" into "a bug in this exact
# binary"; it rides in the exe and shows up in the about card. The stamp must
# carry no spaces: the go tool splits -ldflags on whitespace, so a space in the
# value would be read as the start of the next flag.
$stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
$ldflags = "-X main.version=$Version -X main.buildStamp=$stamp -X main.buildCommit=$Commit"
if (-not $Console) { $ldflags = '-H=windowsgui ' + $ldflags }
# Splatting hands the go tool one argument per element; letting PowerShell
# rebuild the command line from a string is what mangles flags with spaces.
#
# -trimpath rewrites the absolute source paths the compiler would otherwise
# bake into the binary (debug info, panic traces) into module-relative ones,
# so a build made in one checkout does not advertise where that checkout sat.
$goArgs = @('build', '-trimpath', '-ldflags', $ldflags, '-o', $Out, './cmd/desktop')
& go @goArgs
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

$ico = Join-Path $root 'syan-clash.ico'
$icoOut = Join-Path (Split-Path -Parent $Out) 'syan-clash.ico'
if ((Test-Path $ico) -and ($ico -ne $icoOut)) {
    Copy-Item -LiteralPath $ico -Destination $icoOut -Force
}

$exe = Get-Item $Out
$subsystem = if ($Console) { 'console' } else { 'windowsgui (no black window)' }
Write-Host ("built {0}  {1:N1} MB  {2}" -f $exe.FullName, ($exe.Length / 1MB), $subsystem) -ForegroundColor Green