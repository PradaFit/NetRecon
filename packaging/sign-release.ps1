<#
.SYNOPSIS
    Code-sign NetRecon build artifacts (executable and installer).

.DESCRIPTION
    Sign the standalone NetRecon executables and installer with SHA256
    Authenticode. Public signing lets users verify the publisher and reduces
    SmartScreen friction. Partner Center also checks this signature when an
    EXE or MSI is submitted through its installer submission path.

    The standard Microsoft Store MSIX workflow is different. Submit the
    production MSIX unsigned and let the Store sign it after certification.

    This script wraps signtool.exe to support three credential sources:

      1. PFX file on disk             (-PfxPath + -PfxPassword)
      2. Cert store by thumbprint     (-CertThumbprint)
      3. Azure Trusted Signing        (-TrustedSigning + dlib metadata file)

    Self-signed and untrusted-root certificates are for local testing only.

.PARAMETER Files
    One or more PE files (.exe / .dll / .msi) to sign. Wildcards OK.

.PARAMETER PfxPath
    Path to a .pfx file holding the code signing certificate + private key.

.PARAMETER PfxPassword
    SecureString for the PFX. Prompted if -PfxPath supplied without it.

.PARAMETER CertThumbprint
    SHA1 thumbprint of a cert already installed in the local CurrentUser\My
    or LocalMachine\My store (e.g. hardware token / HSM).

.PARAMETER TrustedSigning
    Switch. Use Azure Trusted Signing via the
    Microsoft.Trusted.Signing.Client dlib for signtool.

.PARAMETER TrustedSigningMetadata
    Path to the metadata.json describing your Trusted Signing account,
    certificate profile, and endpoint. Required with -TrustedSigning.

.PARAMETER TimestampUrl
    RFC 3161 timestamp authority. Defaults to DigiCert.
    Alternates: https://timestamp.sectigo.com, https://timestamp.globalsign.com/tsa/r6advanced1

.PARAMETER SigntoolPath
    Optional override for signtool.exe. Auto-discovered if blank.

.PARAMETER Verify
    Run signtool verify /pa /v + Get-AuthenticodeSignature after each sign.

.EXAMPLE
    # PFX on disk (one-off)
    .\packaging\sign-release.ps1 -Files .\dist\NetRecon\NetRecon.exe `
        -PfxPath C:\secure\pradafit-codesign.pfx

.EXAMPLE
    # Hardware token / HSM cert by thumbprint
    .\packaging\sign-release.ps1 -Files .\packaging\Output\NetRecon-Setup-2.0.5.0.exe `
        -CertThumbprint 0123456789ABCDEF0123456789ABCDEF01234567 -Verify

.EXAMPLE
    # Azure Trusted Signing for the public standalone installer
    .\packaging\sign-release.ps1 -Files .\packaging\Output\NetRecon-Setup-2.0.5.0.exe `
        -TrustedSigning -TrustedSigningMetadata .\packaging\trusted-signing.json -Verify

.NOTES
    DO NOT COMMIT pfx, password, private key, or trusted-signing.json files.
    Generated and credential-bearing paths are excluded by .gitignore, but
    review the staged file list before every push.
#>

[CmdletBinding(DefaultParameterSetName = "Pfx")]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$Files,

    [Parameter(ParameterSetName = "Pfx")]
    [string]$PfxPath,

    [Parameter(ParameterSetName = "Pfx")]
    [System.Security.SecureString]$PfxPassword,

    [Parameter(ParameterSetName = "Store")]
    [string]$CertThumbprint,

    [Parameter(ParameterSetName = "TrustedSigning")]
    [switch]$TrustedSigning,

    [Parameter(ParameterSetName = "TrustedSigning")]
    [string]$TrustedSigningMetadata,

    [string]$TimestampUrl = "https://timestamp.digicert.com",

    [string]$SigntoolPath = "",

    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Locate signtool.exe ----
function Find-Signtool {
    param([string]$Override)
    if ($Override -and (Test-Path $Override)) { return $Override }
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
    )
    $found = Get-ChildItem $candidates -ErrorAction SilentlyContinue |
             Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) { return $found.FullName }
    throw "signtool.exe not found. Install Windows 10/11 SDK or pass -SigntoolPath."
}

$signtool = Find-Signtool -Override $SigntoolPath
Write-Host "signtool: $signtool" -ForegroundColor DarkGray

# ---- Expand wildcards ----
$resolved = @()
foreach ($pat in $Files) {
    $hits = Get-Item -Path $pat -ErrorAction SilentlyContinue
    if (-not $hits) { throw "No files matched: $pat" }
    $resolved += $hits.FullName
}
Write-Host ("Files to sign: {0}" -f $resolved.Count) -ForegroundColor Cyan
$resolved | ForEach-Object { Write-Host "  $_" }

# ---- Build signtool argument list per credential source ----
function Get-SignArgs {
    param(
        [string]$Target,
        [string]$PlainPassword = ""
    )
    $base = @(
        "sign",
        "/fd", "SHA256",
        "/td", "SHA256",
        "/tr", $TimestampUrl,
        "/v"
    )

    switch ($PSCmdlet.ParameterSetName) {
        "Pfx" {
            if (-not $PfxPath) { throw "-PfxPath required for Pfx parameter set." }
            if (-not (Test-Path $PfxPath)) { throw "PFX not found: $PfxPath" }
            if (-not $PlainPassword) { throw "PFX password was not supplied securely." }
            return $base + @("/f", $PfxPath, "/p", $PlainPassword, $Target)
        }
        "Store" {
            if (-not $CertThumbprint) { throw "-CertThumbprint required for Store parameter set." }
            return $base + @("/sha1", $CertThumbprint, $Target)
        }
        "TrustedSigning" {
            if (-not $TrustedSigningMetadata) {
                throw "-TrustedSigningMetadata required for Trusted Signing."
            }
            if (-not (Test-Path $TrustedSigningMetadata)) {
                throw "Trusted Signing metadata not found: $TrustedSigningMetadata"
            }
            # Azure Trusted Signing dlib (install: nuget Microsoft.Trusted.Signing.Client)
            $dlibCandidates = @(
                "${env:ProgramFiles}\Microsoft Trusted Signing\bin\x64\Azure.CodeSigning.Dlib.dll",
                "${env:LOCALAPPDATA}\Microsoft\TrustedSigning\Azure.CodeSigning.Dlib.dll"
            )
            $dlib = $dlibCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
            if (-not $dlib) {
                throw "Trusted Signing dlib not found. Install via: nuget install Microsoft.Trusted.Signing.Client"
            }
            return $base + @(
                "/dlib",     $dlib,
                "/dmdf",     $TrustedSigningMetadata,
                $Target
            )
        }
        default { throw "Unknown parameter set: $($PSCmdlet.ParameterSetName)" }
    }
}

# ---- Sign each file ----
foreach ($file in $resolved) {
    Write-Host ""
    Write-Host "==> Signing: $file" -ForegroundColor Cyan
    $passwordPointer = [IntPtr]::Zero
    $plainPassword = ""
    try {
        if ($PSCmdlet.ParameterSetName -eq "Pfx") {
            if (-not $PfxPassword) {
                $PfxPassword = Read-Host "PFX password" -AsSecureString
            }
            $passwordPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
        }
        $args = Get-SignArgs -Target $file -PlainPassword $plainPassword
        & $signtool @args
        if ($LASTEXITCODE -ne 0) { throw "signtool failed (exit $LASTEXITCODE) on $file" }
    }
    finally {
        if ($passwordPointer -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
        }
        $plainPassword = $null
    }
    Write-Host "    Signed OK" -ForegroundColor Green

    if ($Verify) {
        Write-Host ""
        Write-Host "==> Verifying: $file" -ForegroundColor Cyan
        & $signtool verify /pa /v $file
        if ($LASTEXITCODE -ne 0) {
            throw "signtool verification failed (exit $LASTEXITCODE) on $file"
        }
        $sig = Get-AuthenticodeSignature -FilePath $file
        Write-Host ("    Status:      {0}" -f $sig.Status)
        Write-Host ("    Signer:      {0}" -f $sig.SignerCertificate.Subject)
        Write-Host ("    Issuer:      {0}" -f $sig.SignerCertificate.Issuer)
        Write-Host ("    Thumbprint:  {0}" -f $sig.SignerCertificate.Thumbprint)
        Write-Host ("    TS Cert:     {0}" -f $sig.TimeStamperCertificate.Subject)
    }
}

Write-Host ""
Write-Host "Signing complete." -ForegroundColor Green
