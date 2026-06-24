<#
.SYNOPSIS
    Check that no network-related Java code is present.
.DESCRIPTION
    Searches all Java source files for network API references and
    fails if any are found.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/check_no_network_code.ps1
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== Checking for Network Code in Java Sources ===" -ForegroundColor Cyan
Write-Host ""

$srcDir = Join-Path $ProjectRoot "src"
$testDir = Join-Path $ProjectRoot "src/test"

$patterns = @(
    "java\.net\.Socket",
    "java\.net\.URL",
    "java\.net\.HttpURLConnection",
    "java\.net\.http\.HttpClient",
    "org\.apache\.http",
    "okhttp",
    "java\.net\.ServerSocket",
    "java\.net\.DatagramSocket",
    "java\.net\.MulticastSocket"
)

$failed = $false
$allFiles = @()

if (Test-Path $srcDir) {
    $allFiles += Get-ChildItem -Path $srcDir -Recurse -Include "*.java" | Select-Object -ExpandProperty FullName
}

foreach ($file in $allFiles) {
    $content = Get-Content $file -Raw
    $relPath = $file.Substring($ProjectRoot.Length + 1).Replace('\', '/')
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) {
            Write-Host ("[FAIL] Network API found in: " + $relPath) -ForegroundColor Red
            Write-Host ("       Pattern: " + $pattern) -ForegroundColor Red
            # Show the matching line
            $lines = Get-Content $file
            $lineNum = 0
            foreach ($line in $lines) {
                $lineNum++
                if ($line -match $pattern) {
                    Write-Host ("       Line " + $lineNum + ": " + $line.Trim()) -ForegroundColor Yellow
                }
            }
            $failed = $true
        }
    }
}

Write-Host ""
if (-not $failed) {
    Write-Host "[PASS] No network code found in Java sources." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] Network code detected. See details above." -ForegroundColor Red
    exit 1
}