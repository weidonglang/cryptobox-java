<#
.SYNOPSIS
    Check that no build artifacts are tracked by Git.
.DESCRIPTION
    Ensures that *.jar, *.zip, dist/, target/ directories are not
    being tracked by Git (either staged or committed).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/check_no_artifacts.ps1
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== Checking for Build Artifacts in Git ===" -ForegroundColor Cyan
Write-Host ""

$failed = $false
$patterns = @(
    "*.jar",
    "*.zip",
    "*.class",
    "*.log",
    "*.crbx"
)
$dirs = @(
    "/target/",
    "/dist/",
    "/build/"
)

# Check if any tracked files match artifact patterns
$trackedFiles = git ls-files 2>&1
foreach ($file in $trackedFiles) {
    $skip = $false
    # Allow *.crbx in testdata/ (test vectors are intentionally tracked)
    if ($file -like "*.crbx" -and $file -like "testdata/*") {
        $skip = $true
    }
    if (-not $skip) {
        foreach ($pattern in $patterns) {
            if ($file -like $pattern) {
                Write-Host ("[FAIL] Artifact file tracked: " + $file) -ForegroundColor Red
                $failed = $true
            }
        }
    }
    foreach ($dir in $dirs) {
        if ($file.StartsWith($dir.TrimStart('/'))) {
            Write-Host ("[FAIL] Artifact in tracked directory: " + $file) -ForegroundColor Red
            $failed = $true
        }
    }
}

# Check for untracked files in artifact directories
$untracked = git status --porcelain 2>&1
foreach ($line in $untracked) {
    if ($line -match '^\?\? .+') {
        $untrackedFile = $line.Substring(3)
        foreach ($pattern in $patterns) {
            if ($untrackedFile -like $pattern) {
                Write-Host ("[WARN] Untracked artifact: " + $untrackedFile) -ForegroundColor Yellow
            }
        }
        foreach ($dir in $dirs) {
            if ($untrackedFile.StartsWith($dir.TrimStart('/'))) {
                Write-Host ("[WARN] Untracked artifact in: " + $untrackedFile) -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""
if (-not $failed) {
    Write-Host "[PASS] No build artifacts tracked in Git." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] Build artifacts found in Git tracking." -ForegroundColor Red
    exit 1
}