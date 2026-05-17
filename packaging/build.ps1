<#
.SYNOPSIS
    Build the NetRecon Windows installer.

.DESCRIPTION
    Pipeline:
      1. (Optional) Create / refresh the .ico from NetRecon_Images
      2. Run PyInstaller against packaging\NetRecon.spec
      3. Invoke Inno Setup (ISCC.exe) on packaging\NetRecon.iss

.PARAMETER SkipPyInstaller
    Skip the PyInstaller build (useful when only re-running ISCC).

.PARAMETER SkipInstaller
    Skip the Inno Setup compile (only produce the dist\NetRecon folder).

.PARAMETER InnoPath
    Full path to ISCC.exe. If omitted, the script checks the default
    Inno Setup 6 install locations.

.EXAMPLE
    .\packaging\build.ps1

.EXAMPLE
    .\packaging\build.ps1 -SkipInstaller
#>

[CmdletBinding()]
param(
    [switch]$SkipPyInstaller,
    [switch]$SkipInstaller,
    [string]$InnoPath = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$PackDir    = $PSScriptRoot
$DistDir    = Join-Path $RepoRoot "dist"
$BuildDir   = Join-Path $RepoRoot "build"
$OutDir     = Join-Path $PackDir  "Output"
$IconPath   = Join-Path $PackDir  "NetRecon.ico"
$Spec       = Join-Path $PackDir  "NetRecon.spec"
$IssScript  = Join-Path $PackDir  "NetRecon.iss"

Push-Location $RepoRoot
try {
    Write-Host ""
    Write-Host "==> NetRecon installer build" -ForegroundColor Cyan
    Write-Host "    Repo root: $RepoRoot"

    # ---- 0. Ensure PyInstaller is available ----
    if (-not $SkipPyInstaller) {
        $hasPyi = $false
        try {
            python -c "import PyInstaller" 2>$null
            if ($LASTEXITCODE -eq 0) { $hasPyi = $true }
        } catch {}
        if (-not $hasPyi) {
            Write-Host ""
            Write-Host "==> Installing PyInstaller ..." -ForegroundColor Cyan
            python -m pip install --upgrade pyinstaller
            if ($LASTEXITCODE -ne 0) { throw "Failed to install PyInstaller." }
        }
    }

    # ---- 1. Icon ----
    if (-not (Test-Path $IconPath)) {
        Write-Host ""
        Write-Host "==> Generating icon ..." -ForegroundColor Cyan
        python (Join-Path $PackDir "make_icon.py")
        if ($LASTEXITCODE -ne 0) { throw "Icon generation failed." }
    } else {
        Write-Host "    Icon already exists: $IconPath" -ForegroundColor DarkGray
    }

    # ---- 2. PyInstaller ----
    if (-not $SkipPyInstaller) {
        Write-Host ""
        Write-Host "==> Cleaning previous build artifacts ..." -ForegroundColor Cyan
        if (Test-Path $DistDir)  { Remove-Item $DistDir  -Recurse -Force }
        if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }

        Write-Host ""
        Write-Host "==> Running PyInstaller ..." -ForegroundColor Cyan
        python -m PyInstaller --noconfirm --clean $Spec
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }

        $exe = Join-Path $DistDir "NetRecon\NetRecon.exe"
        if (-not (Test-Path $exe)) { throw "Expected exe not found: $exe" }
        Write-Host "    Built: $exe" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "==> Skipping PyInstaller (per -SkipPyInstaller)." -ForegroundColor Yellow
    }

    # ---- 3. Inno Setup ----
    if (-not $SkipInstaller) {
        # Mirror LICENSE and DISCLAIMER.md as .txt so Inno's LicenseFile/
        # InfoBeforeFile (which expect .txt or .rtf) accept them cleanly.
        Copy-Item -Force (Join-Path $RepoRoot "LICENSE")       (Join-Path $PackDir "LICENSE.txt")
        Copy-Item -Force (Join-Path $RepoRoot "DISCLAIMER.md") (Join-Path $PackDir "DISCLAIMER.txt")

        if (-not $InnoPath) {
            $candidates = @(
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
            )
            $InnoPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        }

        if (-not $InnoPath -or -not (Test-Path $InnoPath)) {
            throw "ISCC.exe not found. Install Inno Setup 6 from https://jrsoftware.org/isdl.php or pass -InnoPath."
        }

        Write-Host ""
        Write-Host "==> Compiling installer with Inno Setup ..." -ForegroundColor Cyan
        Write-Host "    ISCC: $InnoPath"
        & $InnoPath $IssScript
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed." }

        $built = Get-ChildItem -Path $OutDir -Filter "NetRecon-Setup-*.exe" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($built) {
            Write-Host ""
            Write-Host "==> Installer ready:" -ForegroundColor Green
            Write-Host "    $($built.FullName)"
        }
    } else {
        Write-Host ""
        Write-Host "==> Skipping installer compile (per -SkipInstaller)." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
}
finally {
    Pop-Location
}
