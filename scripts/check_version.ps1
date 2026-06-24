<#
.SYNOPSIS
    Check version consistency across the project.
.DESCRIPTION
    Verifies that VERSION, pom.xml, README.md, docs/user_guide.md,
    docs/release_notes.md, and scripts/package_release.ps1 all have
    the same version number.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/check_version.ps1
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$versionFile = Join-Path $ProjectRoot "VERSION"
$pomFile = Join-Path $ProjectRoot "pom.xml"
$readmeFile = Join-Path $ProjectRoot "README.md"
$userGuideFile = Join-Path $ProjectRoot "docs/user_guide.md"
$releaseNotesFile = Join-Path $ProjectRoot "docs/release_notes.md"
$packageScriptFile = Join-Path $ProjectRoot "scripts/package_release.ps1"

Write-Host "=== Checking Version Consistency ===" -ForegroundColor Cyan
Write-Host ""

# Read expected version from VERSION file
if (-not (Test-Path $versionFile)) {
    Write-Host "[FAIL] VERSION file not found at: $versionFile" -ForegroundColor Red
    exit 1
}
$expectedVersion = (Get-Content $versionFile).Trim()
Write-Host "Expected version: $expectedVersion" -ForegroundColor White
Write-Host ""

function Check-Version {
    param(
        [string]$FilePath,
        [string]$Label,
        [string]$Pattern
    )
    if (-not (Test-Path $FilePath)) {
        Write-Host ("[SKIP] " + $Label + ": file not found") -ForegroundColor Yellow
        return $true
    }
    $content = Get-Content $FilePath -Raw
    if ($content -match $Pattern) {
        $found = $matches[1].Trim()
        if ($found -eq $expectedVersion) {
            Write-Host ("[PASS] " + $Label + ": " + $found) -ForegroundColor Green
            return $true
        } else {
            Write-Host ("[FAIL] " + $Label + ": expected '" + $expectedVersion + "', found '" + $found + "'") -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host ("[FAIL] " + $Label + ": version pattern not found") -ForegroundColor Red
        return $false
    }
}

# Check all files
$pomOk = Check-Version -FilePath $pomFile -Label "pom.xml" -Pattern '<version>([^<]+)</version>'
$readmeOk = Check-Version -FilePath $readmeFile -Label "README.md" -Pattern '(\d+\.\d+\.\d+)'
$userGuideOk = Check-Version -FilePath $userGuideFile -Label "docs/user_guide.md" -Pattern '(\d+\.\d+\.\d+)'
$releaseNotesOk = Check-Version -FilePath $releaseNotesFile -Label "docs/release_notes.md" -Pattern '(\d+\.\d+\.\d+)'
$packageScriptOk = Check-Version -FilePath $packageScriptFile -Label "scripts/package_release.ps1" -Pattern '(\d+\.\d+\.\d+)'

Write-Host ""
if ($pomOk -and $readmeOk -and $userGuideOk -and $releaseNotesOk -and $packageScriptOk) {
    Write-Host "[PASS] All version checks passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] Version consistency check failed." -ForegroundColor Red
    exit 1
}