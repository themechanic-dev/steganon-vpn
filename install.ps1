#Requires -RunAsAdministrator
<#
    Installing Steganon on Windows.

    It brings what is missing itself: a clean machine has neither Python nor
    OpenVPN, and there is no point asking somebody to go find them first.

    WARNING: this tool changes the firewall rules of the entire machine. Once
    it is on, no traffic leaves outside the tunnel beyond the local network.
    Try it in a virtual machine first.

    Usage:  powershell -ExecutionPolicy Bypass -File install.ps1
#>

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Root    = "$env:ProgramFiles\Steganon"
$DataDir = "$env:ProgramData\Steganon"
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path

function Step($text) { Write-Host "▸ $text" -ForegroundColor Cyan }
function Ok($text)   { Write-Host "  ✓ $text" -ForegroundColor Green }
function Warn($text) { Write-Host "  ! $text" -ForegroundColor Yellow }

# ── Where Python actually is ──────────────────────────────────────────────
#
# "Get-Command python" is not reliable: Windows plants a fake python.exe that
# merely opens the Microsoft Store. We look for the real interpreter in the
# places the installers put it.
function Find-Python {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe"
        "$env:ProgramFiles\Python3*\python.exe"
        "C:\Python3*\python.exe"
    )
    foreach ($pattern in $candidates) {
        $hit = Get-ChildItem $pattern -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Install-Dependency($id, $label, $probe) {
    if (& $probe) { Ok "$label — already present"; return }
    Step "Installing: $label"
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "$label is missing and there is no winget to install it. Install it manually."
    }
    winget install --id $id --silent --accept-package-agreements `
        --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
    if (& $probe) { Ok "$label" } else { throw "Installing $label failed." }
}

# ── 1. Dependencies ───────────────────────────────────────────────────────
Write-Host ""
Step "Checking prerequisites"

Install-Dependency 'Python.Python.3.12' 'Python' { (Find-Python) -ne $null }
Install-Dependency 'OpenVPNTechnologies.OpenVPN' 'OpenVPN' {
    Test-Path "$env:ProgramFiles\OpenVPN\bin\openvpn.exe"
}

$Python = Find-Python
if (-not $Python) { throw "Python was not found after installation." }

Step "GUI library"
& $Python -m pip install --quiet --upgrade pip 2>&1 | Out-Null
& $Python -m pip install --quiet PySide6 2>&1 | Out-Null
$hasQt = (& $Python -c "import PySide6; print('ok')" 2>$null) -eq 'ok'
if ($hasQt) { Ok "PySide6" } else { Warn "PySide6 did not install — only the command line will work" }

# ── 2. Copying ────────────────────────────────────────────────────────────
Step "Copying files"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
Copy-Item "$Here\steganon" -Destination $Root -Recurse -Force
Ok $Root

# The data folder is world readable: the GUI runs without privileges and needs
# the location list. The secrets are protected separately, as they are
# written.
New-Item -ItemType Directory -Force -Path $DataDir, "$DataDir\profiles" | Out-Null
Ok $DataDir

# ── 3. Commands ───────────────────────────────────────────────────────────
Step "Commands"
$launcher = @"
@echo off
"$Python" -c "import sys; sys.path.insert(0, r'$Root'); from steganon.cli import main; sys.exit(main())" %*
"@
Set-Content -Path "$Root\steganon.cmd" -Value $launcher -Encoding ASCII

# "pythonw" runs without a console window — otherwise a black rectangle would
# open behind the GUI on every start.
$PythonW = $Python -replace 'python\.exe$', 'pythonw.exe'
if (-not (Test-Path $PythonW)) { $PythonW = $Python }
$guiLauncher = @"
@echo off
start "" "$PythonW" -c "import sys; sys.path.insert(0, r'$Root'); from steganon.gui_qt import main; sys.exit(main())" %*
"@
Set-Content -Path "$Root\steganon-gui.cmd" -Value $guiLauncher -Encoding ASCII

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike "*$Root*") {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$Root", 'Machine')
    Ok "added to the search path (takes effect in a new window)"
}
Ok "steganon, steganon-gui"

# ── 4. Service ────────────────────────────────────────────────────────────
Step "Service"
& $Python -c "import sys; sys.path.insert(0, r'$Root'); from steganon.backends import windows_service as s; s.install()" 2>&1 | Out-Null
if (Get-Service Steganon -ErrorAction SilentlyContinue) { Ok "Steganon" }
else { Warn "The service was not created — see: steganon service install" }

# ── 5. Shortcut ───────────────────────────────────────────────────────────
$startMenu = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Steganon.lnk"
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($startMenu)
$link.TargetPath = "$Root\steganon-gui.cmd"
$link.WorkingDirectory = $Root
$link.Description = 'Steganon — all traffic through the tunnel, or none at all'
$link.Save()
Ok "start menu shortcut"

Write-Host ""
Write-Host "Done. Next steps:" -ForegroundColor White
Write-Host "  1. Add a location:  steganon add <folder-or-file.ovpn>"
Write-Host "  2. Its credentials: steganon credentials <name>"
Write-Host "     (repeat 1-2 for every location you want)"
Write-Host "  3. Try it:          steganon up   ->   steganon status"
Write-Host "  4. Make it permanent: steganon autostart on"
Write-Host ""
Write-Host "If something goes wrong:  steganon firewall off" -ForegroundColor Yellow
Write-Host ""
