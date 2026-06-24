<#
.SYNOPSIS
    Count total lines of code in the project.
.DESCRIPTION
    Counts lines in all .java, .md, .ps1, .xml, .json, .gitignore
    files in the project, excluding target/, dist/, and build/ directories.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/count_lines.ps1
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$includeExtensions = @(
    "*.java",
    "*.md",
    "*.ps1",
    "*.xml",
    "*.json",
    "*.gitignore"
)

$excludeDirs = @(
    "target",
    "dist",
    "build",
    ".git"
)

Write-Host "=== Line Count Report ===" -ForegroundColor Cyan
Write-Host ""

$totalLines = 0
$fileCount = 0
$details = @{}

foreach ($ext in $includeExtensions) {
    $files = Get-ChildItem -Path $ProjectRoot -Recurse -Filter $ext |
        Where-Object {
            $exclude = $false
            foreach ($dir in $excludeDirs) {
                if ($_.FullName -match [regex]::Escape($dir)) {
                    $exclude = $true
                    break
                }
            }
            -not $exclude
        }
    $extLines = 0
    $extFiles = 0
    foreach ($file in $files) {
        $lineCount = (Get-Content $file.FullName | Measure-Object -Line).Lines
        $extLines += $lineCount
        $extFiles++
    }
    if ($extFiles -gt 0) {
        $category = $ext.TrimStart('*')
        Write-Host ("  " + $category + ": " + $extLines + " lines (" + $extFiles + " files)") -ForegroundColor White
        $totalLines += $extLines
        $fileCount += $extFiles
    }
}

Write-Host ""
Write-Host ("Total: " + $totalLines + " lines in " + $fileCount + " files") -ForegroundColor Green
Write-Host ""

if ($totalLines -ge 5000) {
    Write-Host "[PASS] Line count target met (>= 5000)." -ForegroundColor Green
    exit 0
} else {
    Write-Host ("[INFO] Line count " + $totalLines + " / 5000 target.") -ForegroundColor Yellow
    exit 0
}