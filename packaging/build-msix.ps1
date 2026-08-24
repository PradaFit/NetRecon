<#
.SYNOPSIS
    Build a sideloadable MSIX package for NetRecon.

.DESCRIPTION
    Pipeline:
      1. (Optional) Run PyInstaller to refresh dist\NetRecon.
      2. Generate Assets PNGs from packaging\NetRecon.ico (Pillow).
      3. Stage payload + manifest under packaging\msix-stage.
      4. Pack the directory into packaging\Output\NetRecon-<ver>-x64.msix
         via makeappx.exe from the Windows SDK.
      5. (Optional) Sign the MSIX with a self-signed dev cert from the
         CurrentUser certificate store for local sideload only.

    Does NOT touch the Inno Setup .exe installer flow. Leaves dist\
    untouched if -SkipPyInstaller is passed.

.PARAMETER SkipPyInstaller
    Reuse the existing dist\NetRecon folder instead of rebuilding.

.PARAMETER SkipAssets
    Reuse existing packaging\Assets folder instead of regenerating.

.PARAMETER Sign
    Sign the produced MSIX with the local dev cert. REQUIRED for
    Add-AppxPackage to accept it on your machine.

.PARAMETER InstallAfterBuild
    Sideload the package via Add-AppxPackage once it is built+signed.

.PARAMETER DevCertSubject
    Subject of the self-signed cert. MUST match Publisher in
    AppxManifest.dev.xml exactly. Default: CN=PradaFitDev.

.PARAMETER Version
    4-part MSIX version. Overrides the manifest if supplied. Default reads
    the manifest. Example: 2.0.1.0

.PARAMETER DistPath
    Optional PyInstaller payload directory. Relative paths are resolved from
    the repository root. Default: dist\NetRecon

.PARAMETER StagePath
    Optional staging directory. Relative paths are resolved from the
    repository root. Default: packaging\msix-stage

.PARAMETER OutputDirectory
    Optional package output directory. Relative paths are resolved from the
    repository root. Default: packaging\Output

.EXAMPLE
    .\packaging\build-msix.ps1                          # build + pack (no sign)
    .\packaging\build-msix.ps1 -Sign                    # build + pack + sign
    .\packaging\build-msix.ps1 -Sign -InstallAfterBuild # full local install
    .\packaging\build-msix.ps1 -SkipPyInstaller -Sign   # reuse existing dist\
#>

[CmdletBinding()]
param(
    [switch]$SkipPyInstaller,
    [switch]$SkipAssets,
    [switch]$Sign,
    [switch]$InstallAfterBuild,
    [string]$DevCertSubject = "CN=PradaFitDev",
    [string]$Version = "",
    [string]$DistPath = "",
    [string]$StagePath = "",
    [string]$OutputDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($InstallAfterBuild -and -not $Sign) {
    throw "-InstallAfterBuild requires -Sign (unsigned MSIX packages cannot be sideloaded)."
}
if ($DistPath -and -not $SkipPyInstaller) {
    throw "-DistPath requires -SkipPyInstaller because build.ps1 writes to dist\NetRecon."
}

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$PackDir    = $PSScriptRoot

function Resolve-RepoPath {
    param(
        [string]$Value,
        [string]$DefaultRelative
    )
    $candidate = if ($Value) { $Value } else { $DefaultRelative }
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $RepoRoot $candidate
    }
    return [System.IO.Path]::GetFullPath($candidate)
}

$DistDir    = Resolve-RepoPath -Value $DistPath -DefaultRelative "dist\NetRecon"
$StoreManifest = Join-Path $PackDir "AppxManifest.xml"
$DevManifest   = Join-Path $PackDir "AppxManifest.dev.xml"
$Manifest      = if ($Sign -or $InstallAfterBuild) { $DevManifest } else { $StoreManifest }
$AssetsSrc  = Join-Path $PackDir  "Assets"
$Stage      = Resolve-RepoPath -Value $StagePath -DefaultRelative "packaging\msix-stage"
$OutDir     = Resolve-RepoPath -Value $OutputDirectory -DefaultRelative "packaging\Output"
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$RequiredDocs = @("LICENSE", "PRIVACY.md", "DISCLAIMER.md")

$repoPrefix = $RepoRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
foreach ($managedPath in @($Stage, $OutDir)) {
    if (-not $managedPath.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Managed build path must remain under the repository root: $managedPath"
    }
    if ($managedPath -in @($RepoRoot, $PackDir, $DistDir)) {
        throw "Refusing unsafe managed build path: $managedPath"
    }
}

if (-not (Test-Path -LiteralPath $Manifest)) {
    throw "MSIX manifest not found: $Manifest"
}
foreach ($requiredDoc in $RequiredDocs) {
    $requiredPath = Join-Path $RepoRoot $requiredDoc
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required MSIX document not found: $requiredPath"
    }
}

# ---- Tooling discovery ----
function Get-SdkTool {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $hits = Get-ChildItem -Path @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\$Name",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\$Name"
    ) -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
    if ($hits) { return $hits[0].FullName }
    throw "$Name not found. Install Windows 10/11 SDK."
}

$Makeappx = Get-SdkTool -Name "makeappx.exe"
$Signtool = Get-SdkTool -Name "signtool.exe"

Push-Location $RepoRoot
try {
    Write-Host ""
    Write-Host "==> NetRecon MSIX build" -ForegroundColor Cyan
    Write-Host "    makeappx: $Makeappx" -ForegroundColor DarkGray
    Write-Host "    signtool: $Signtool" -ForegroundColor DarkGray

    # ---- 1. PyInstaller (optional) ----
    if (-not $SkipPyInstaller) {
        Write-Host ""
        Write-Host "==> Running PyInstaller ..." -ForegroundColor Cyan
        & (Join-Path $PackDir "build.ps1") -SkipInstaller
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller step failed." }
    } else {
        Write-Host "    Skipping PyInstaller (per flag)." -ForegroundColor Yellow
    }
    if (-not (Test-Path $DistDir)) { throw "dist\NetRecon not found. Build PyInstaller first." }
    foreach ($requiredExe in @("NetRecon.exe", "NetRecon-CLI.exe")) {
        $requiredPath = Join-Path $DistDir $requiredExe
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "PyInstaller output is incomplete: $requiredPath"
        }
    }

    # ---- 2. Assets ----
    if (-not $SkipAssets -or -not (Test-Path $AssetsSrc)) {
        Write-Host ""
        Write-Host "==> Generating MSIX assets from NetRecon.ico ..." -ForegroundColor Cyan
        if (-not (Test-Path -LiteralPath $VenvPython)) {
            throw ".venv is missing. Run packaging\build.ps1 first."
        }
        & $VenvPython (Join-Path $PackDir "make_msix_assets.py")
        if ($LASTEXITCODE -ne 0) { throw "Asset generation failed." }
    } else {
        Write-Host "    Reusing existing Assets folder." -ForegroundColor Yellow
    }

    # ---- 3. Resolve version + stage ----
    [xml]$manifestXml = Get-Content $Manifest
    if ($Version) {
        $manifestXml.Package.Identity.Version = $Version
    }
    $resolvedVersion = $manifestXml.Package.Identity.Version
    if ($resolvedVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "Manifest Version must be 4-part (x.y.z.w). Got: $resolvedVersion"
    }

    Write-Host ""
    Write-Host "==> Staging payload at $Stage" -ForegroundColor Cyan
    if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
    New-Item $Stage -ItemType Directory | Out-Null

    # PyInstaller payload
    Copy-Item "$DistDir\*" $Stage -Recurse -Force

    # Assets
    Copy-Item $AssetsSrc (Join-Path $Stage "Assets") -Recurse -Force

    # Legal and privacy files are part of the release payload.
    foreach ($requiredDoc in $RequiredDocs) {
        $src = Join-Path $RepoRoot $requiredDoc
        Copy-Item -LiteralPath $src -Destination $Stage -Force
    }

    # Manifest with possibly-bumped version
    $manifestXml.Save((Join-Path $Stage "AppxManifest.xml"))

    # ---- 4. Pack ----
    if (-not (Test-Path $OutDir)) { New-Item $OutDir -ItemType Directory | Out-Null }
    $Msix = Join-Path $OutDir "NetRecon-$resolvedVersion-x64.msix"
    if (Test-Path $Msix) { Remove-Item $Msix -Force }

    Write-Host ""
    Write-Host "==> Packing MSIX ..." -ForegroundColor Cyan
    & $Makeappx pack /d $Stage /p $Msix /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed." }
    Write-Host "    Built: $Msix" -ForegroundColor Green

    # ---- 5. Sign (local dev cert) ----
    if ($Sign) {
        Write-Host ""
        Write-Host "==> Preparing dev signing cert ..." -ForegroundColor Cyan

        $cert = Get-ChildItem Cert:\CurrentUser\My |
                Where-Object { $_.Subject -eq $DevCertSubject -and $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.3" } |
                Sort-Object NotAfter -Descending | Select-Object -First 1

        if (-not $cert) {
            Write-Host "    Creating new self-signed cert: $DevCertSubject" -ForegroundColor Yellow
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $DevCertSubject `
                -KeyUsage DigitalSignature `
                -FriendlyName "NetRecon MSIX Dev" `
                -CertStoreLocation Cert:\CurrentUser\My `
                -NotAfter (Get-Date).AddYears(3) `
                -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3","2.5.29.19={text}")
        } else {
            Write-Host "    Reusing existing dev cert (thumbprint $($cert.Thumbprint))." -ForegroundColor DarkGray
        }

        # Verify Publisher CN in manifest matches the cert subject exactly,
        # otherwise signtool succeeds but Add-AppxPackage rejects the package.
        $publisher = $manifestXml.Package.Identity.Publisher
        if ($publisher -ne $DevCertSubject) {
            throw "Publisher mismatch: manifest='$publisher', cert='$DevCertSubject'. Re-run with -DevCertSubject `"$publisher`" or edit AppxManifest.xml."
        }

        Write-Host ""
        Write-Host "==> Signing MSIX ..." -ForegroundColor Cyan
        & $Signtool sign /fd SHA256 /sha1 $cert.Thumbprint /s My $Msix
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed." }
        Write-Host "    Signed." -ForegroundColor Green

        # Trust the cert on this machine (one-time; harmless to re-run).
        $cerPath = Join-Path $PackDir "dev-msix.cer"
        Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
        $existing = Get-ChildItem Cert:\LocalMachine\TrustedPeople |
                    Where-Object Thumbprint -eq $cert.Thumbprint
        if (-not $existing) {
            Write-Host "    Importing dev cert into LocalMachine\TrustedPeople (requires admin)." -ForegroundColor Yellow
            try {
                Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
                Write-Host "    Trust established." -ForegroundColor Green
            } catch {
                Write-Warning "Could not auto-import to LocalMachine\TrustedPeople. Run this in an elevated PowerShell:"
                Write-Warning "  Import-Certificate -FilePath '$cerPath' -CertStoreLocation Cert:\LocalMachine\TrustedPeople"
            }
        }
    }

    # ---- 6. Install (optional) ----
    if ($InstallAfterBuild) {
        Write-Host ""
        Write-Host "==> Installing MSIX ..." -ForegroundColor Cyan
        Add-AppxPackage -Path $Msix
        Write-Host "    Installed. Launch from Start menu > NetRecon." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "MSIX ready: $Msix" -ForegroundColor Green
}
finally {
    Pop-Location
}
