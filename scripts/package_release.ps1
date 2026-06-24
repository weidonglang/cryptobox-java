<#
.SYNOPSIS
    Package the Cryptobox Java release into a distributable ZIP archive.
.DESCRIPTION
    Builds the release JAR and creates a ZIP archive containing:
    - cryptobox.jar (executable fat JAR)
    - README.md and LICENSE
    - docs/ directory (all documentation)
    - examples/ directory (sample files)
    - scripts/ directory (utility scripts)
    
    Excludes: target/, .git/, src/, testdata/, and *.crbx files.
    The ZIP is placed in dist/cryptobox-java-v<VERSION>.zip.
.EXAMPLE
    powershell -File scripts/package_release.ps1
#>

$ScriptVersion = "1.0.0"
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== Cryptobox Java: Packaging Release ZIP ===" -ForegroundColor Cyan
Write-Host ""

# Read version from VERSION file
$versionFile = Join-Path $ProjectRoot "VERSION"
if (-not (Test-Path $versionFile)) {
    Write-Host "[FAIL] VERSION file not found." -ForegroundColor Red
    exit 1
}
$version = (Get-Content $versionFile -Raw).Trim()
Write-Host "Version: $version" -ForegroundColor Yellow

# Ensure JAR is built
$jarPath = Join-Path $ProjectRoot "target\cryptobox.jar"
if (-not (Test-Path $jarPath)) {
    Write-Host "[INFO] cryptobox.jar not found. Running build_release.ps1..." -ForegroundColor Yellow
    $buildScript = Join-Path $ProjectRoot "scripts\build_release.ps1"
    & $buildScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] Build failed. Cannot package release." -ForegroundColor Red
        exit 1
    }
}

# Verify JAR exists after build
if (-not (Test-Path $jarPath)) {
    Write-Host "[FAIL] cryptobox.jar still not found after build." -ForegroundColor Red
    exit 1
}
$jarSize = (Get-Item $jarPath).Length
Write-Host "[OK] cryptobox.jar ($('{0:N0}' -f $jarSize) bytes)" -ForegroundColor Green

# Create dist directory
$distDir = Join-Path $ProjectRoot "dist"
if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

# Define ZIP path
$zipName = "cryptobox-java-v$version.zip"
$zipPath = Join-Path $distDir $zipName

# Remove existing ZIP if present
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

# Build file list for ZIP (relative paths to ProjectRoot)
$filesToInclude = @()

# Always include cryptobox.jar
$filesToInclude += "target\cryptobox.jar"

# Include README and LICENSE if they exist
if (Test-Path (Join-Path $ProjectRoot "README.md")) { $filesToInclude += "README.md" }
if (Test-Path (Join-Path $ProjectRoot "LICENSE")) { $filesToInclude += "LICENSE" }

# Include docs directory recursively
$docsDir = Join-Path $ProjectRoot "docs"
if (Test-Path $docsDir) {
    Get-ChildItem -Path $docsDir -Recurse -File | ForEach-Object {
        $relative = $_.FullName.Substring($ProjectRoot.Length + 1)
        $filesToInclude += $relative
    }
}

# Include examples directory recursively (excluding *.crbx)
$examplesDir = Join-Path $ProjectRoot "examples"
if (Test-Path $examplesDir) {
    Get-ChildItem -Path $examplesDir -Recurse -File | Where-Object {
        $_.Extension -notin @('.crbx')
    } | ForEach-Object {
        $relative = $_.FullName.Substring($ProjectRoot.Length + 1)
        $filesToInclude += $relative
    }
}

# Include scripts directory recursively (only .ps1 files)
$scriptsDir = Join-Path $ProjectRoot "scripts"
if (Test-Path $scriptsDir) {
    Get-ChildItem -Path $scriptsDir -Recurse -File -Filter "*.ps1" | ForEach-Object {
        $relative = $_.FullName.Substring($ProjectRoot.Length + 1)
        $filesToInclude += $relative
    }
}

Write-Host ""
Write-Host "--- Creating ZIP archive ---" -ForegroundColor Yellow
Write-Host "  Archive: $zipName"
Write-Host "  Files to include: $($filesToInclude.Count)"

# Create ZIP using Compress-Archive (built-in PowerShell 5+)
$tempDir = Join-Path $env:TEMP "cryptobox-package-$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Copy all files to a temporary directory preserving structure
    foreach ($file in $filesToInclude) {
        $fullPath = Join-Path $ProjectRoot $file
        if (Test-Path $fullPath) {
            $targetPath = Join-Path $tempDir $file
            $targetDir = Split-Path $targetPath -Parent
            if (-not (Test-Path $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
            Copy-Item -Path $fullPath -Destination $targetPath -Force
            Write-Host "  Added: $file" -ForegroundColor Gray
        } else {
            Write-Host "  [WARN] File not found, skipping: $file" -ForegroundColor Yellow
        }
    }
    
    # Create ZIP using Compress-Archive
    Compress-Archive -Path "$tempDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
} finally {
    # Clean up temp directory
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Verify ZIP was created
if (Test-Path $zipPath) {
    $zipSize = (Get-Item $zipPath).Length
    Write-Host ""
    Write-Host "[PASS] Release package created: $zipPath" -ForegroundColor Green
    Write-Host "[PASS] Size: $('{0:N0}' -f $zipSize) bytes" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] Failed to create ZIP archive." -ForegroundColor Red
    exit 1
}