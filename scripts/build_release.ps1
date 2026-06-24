<#
.SYNOPSIS
    Build the Cryptobox Java release JAR.
.DESCRIPTION
    Invokes Maven clean package to produce the fat JAR at target/cryptobox.jar.
.EXAMPLE
    powershell -File scripts/build_release.ps1
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== Cryptobox Java: Building Release JAR ===" -ForegroundColor Cyan
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
Write-Host "--- Running: mvn clean package -DskipTests ---" -ForegroundColor Yellow
Write-Host ""

# Execute mvn clean package, skip tests for faster builds
$output = mvn clean package -DskipTests 2>&1
$exitCode = $LASTEXITCODE

Write-Host $output

if ($exitCode -eq 0) {
    Write-Host ""
    # Verify JAR was created
    $jarPath = Join-Path $ProjectRoot "target\cryptobox.jar"
    if (Test-Path $jarPath) {
        $jarSize = (Get-Item $jarPath).Length
        Write-Host "[PASS] cryptobox.jar created successfully ($('{0:N0}' -f $jarSize) bytes)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] cryptobox.jar not found at target/cryptobox.jar" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[FAIL] Build failed with exit code: $exitCode" -ForegroundColor Red
}

exit $exitCode