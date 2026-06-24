<#
.SYNOPSIS
    Run all tests for the Cryptobox Java project.
.DESCRIPTION
    Executes Maven build with tests (mvn verify) and reports results.
.EXAMPLE
    powershell -File scripts/run_all_tests.ps1
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== Cryptobox Java: Running All Tests ===" -ForegroundColor Cyan
Write-Host ""

# Check Java version
$javaVersion = java --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Java is not available." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Java: $($javaVersion[0])" -ForegroundColor Green

# Check Maven
$mvnVersion = mvn --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Maven is not available." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Maven: $($mvnVersion -match 'Apache Maven' | ForEach-Object { $_ })" -ForegroundColor Green

Write-Host ""
Write-Host "--- Running: mvn verify ---" -ForegroundColor Yellow
Write-Host ""

# Execute mvn verify
$output = mvn verify 2>&1
$exitCode = $LASTEXITCODE

Write-Host $output

if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "[PASS] All tests passed!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[FAIL] Tests failed with exit code: $exitCode" -ForegroundColor Red
}

exit $exitCode