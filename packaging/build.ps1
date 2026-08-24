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

.PARAMETER Sign
    Sign both NetRecon executables after PyInstaller and the final installer
    after Inno Setup.
    Requires one of: -PfxPath, -CertThumbprint, or -TrustedSigning.

.PARAMETER PfxPath
    Path to a code-signing .pfx (forwarded to sign-release.ps1).

.PARAMETER CertThumbprint
    SHA1 thumbprint of a cert in your CurrentUser\My or LocalMachine\My store.

.PARAMETER TrustedSigning
    Use Azure Trusted Signing (forwarded to sign-release.ps1).

.PARAMETER TrustedSigningMetadata
    Path to Trusted Signing metadata.json.

.EXAMPLE
    .\packaging\build.ps1

.EXAMPLE
    .\packaging\build.ps1 -SkipInstaller

.EXAMPLE
    .\packaging\build.ps1 -Sign -TrustedSigning `
        -TrustedSigningMetadata .\packaging\trusted-signing.json
#>

[CmdletBinding()]
param(
    [switch]$SkipPyInstaller,
    [switch]$SkipInstaller,
    [string]$InnoPath = "",
    [switch]$Sign,
    [string]$PfxPath = "",
    [string]$CertThumbprint = "",
    [switch]$TrustedSigning,
    [string]$TrustedSigningMetadata = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$PackDir    = $PSScriptRoot
$DistDir    = Join-Path $RepoRoot "dist"
$BuildDir   = Join-Path $RepoRoot "build"
$OutDir     = Join-Path $PackDir  "Output"
$IconPath   = Join-Path $PackDir  "NetRecon.ico"
$Spec       = Join-Path $PackDir  "NetRecon.spec"
$IssScript  = Join-Path $PackDir  "NetRecon.iss"
$SignScript = Join-Path $PackDir  "sign-release.ps1"
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$BuildRequirements = Join-Path $RepoRoot "requirements-build.txt"

# Validate signing creds early so the user doesn't wait through a full build
# only to discover a missing flag at the signing step.
if ($Sign) {
    $credCount = @($PfxPath, $CertThumbprint, $TrustedSigning.IsPresent) |
                 Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    if ($credCount -eq 0) {
        throw "-Sign requires one of: -PfxPath <path>, -CertThumbprint <sha1>, or -TrustedSigning."
    }
    if (-not (Test-Path $SignScript)) {
        throw "sign-release.ps1 not found at $SignScript."
    }
}

function Invoke-Sign {
    param([string[]]$Targets)
    if (-not $Sign) { return }
    $signArgs = @{ Files = $Targets; Verify = $true }
    if ($PfxPath)                { $signArgs.PfxPath = $PfxPath }
    if ($CertThumbprint)         { $signArgs.CertThumbprint = $CertThumbprint }
    if ($TrustedSigning)         { $signArgs.TrustedSigning = $true }
    if ($TrustedSigningMetadata) { $signArgs.TrustedSigningMetadata = $TrustedSigningMetadata }
    & $SignScript @signArgs
    if ($LASTEXITCODE -ne 0) { throw "Signing step failed." }
}

Push-Location $RepoRoot
try {
    Write-Host ""
    Write-Host "==> NetRecon installer build" -ForegroundColor Cyan
    Write-Host "    Repo root: $RepoRoot"

    # ---- 0. Prepare an isolated, version-pinned build environment ----
    if (-not $SkipPyInstaller) {
        if (-not (Test-Path -LiteralPath $VenvPython)) {
            Write-Host ""
            Write-Host "==> Creating isolated .venv ..." -ForegroundColor Cyan
            py -3.12 -m venv (Join-Path $RepoRoot ".venv")
            if ($LASTEXITCODE -ne 0) { throw "Failed to create .venv." }
        }
        & $VenvPython -m pip install --disable-pip-version-check -r $BuildRequirements
        if ($LASTEXITCODE -ne 0) { throw "Failed to install pinned build requirements." }
    }

    # ---- 1. Icon ----
    if (-not (Test-Path $IconPath)) {
        Write-Host ""
        Write-Host "==> Generating icon ..." -ForegroundColor Cyan
        & $VenvPython (Join-Path $PackDir "make_icon.py")
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
        & $VenvPython -m PyInstaller --noconfirm --clean $Spec
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }

        $exe = Join-Path $DistDir "NetRecon\NetRecon.exe"
        $cliExe = Join-Path $DistDir "NetRecon\NetRecon-CLI.exe"
        foreach ($requiredExe in @($exe, $cliExe)) {
            if (-not (Test-Path -LiteralPath $requiredExe)) {
                throw "Expected executable not found: $requiredExe"
            }
            Write-Host "    Built: $requiredExe" -ForegroundColor Green
        }

        # Sign both PyInstaller executables before Inno Setup packs them so
        # the installed GUI and CLI payloads carry valid signatures.
        if ($Sign) {
            Write-Host ""
            Write-Host "==> Signing NetRecon executables ..." -ForegroundColor Cyan
            Invoke-Sign -Targets @($exe, $cliExe)
        }
    } else {
        Write-Host ""
        Write-Host "==> Skipping PyInstaller (per -SkipPyInstaller)." -ForegroundColor Yellow
        if (-not $SkipInstaller) {
            foreach ($requiredExe in @(
                (Join-Path $DistDir "NetRecon\NetRecon.exe"),
                (Join-Path $DistDir "NetRecon\NetRecon-CLI.exe")
            )) {
                if (-not (Test-Path -LiteralPath $requiredExe)) {
                    throw "Existing distribution is incomplete: $requiredExe"
                }
            }
        }
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

            # Sign the final installer so users can verify the publisher and
            # to reduce SmartScreen friction. Partner Center also validates
            # this signature when using its EXE/MSI submission path.
            if ($Sign) {
                Write-Host ""
                Write-Host "==> Signing installer ..." -ForegroundColor Cyan
                Invoke-Sign -Targets @($built.FullName)
            }
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
