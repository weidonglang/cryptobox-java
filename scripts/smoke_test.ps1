<#
.SYNOPSIS
    Perform a quick smoke test on the built cryptobox.jar.
.DESCRIPTION
    Tests that the JAR runs --help, can generate a key, encrypt and decrypt a file.
.EXAMPLE
    powershell -File scripts/smoke_test.ps1
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== Cryptobox Java: Smoke Test ===" -ForegroundColor Cyan
Write-Host ""

# Locate the JAR
$jarPath = Join-Path $ProjectRoot "target\cryptobox.jar"
if (-not (Test-Path $jarPath)) {
    Write-Host "[FAIL] cryptobox.jar not found. Run scripts/build_release.ps1 first." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Found cryptobox.jar" -ForegroundColor Green

# Create a temp directory for testing
$tempDir = Join-Path $ProjectRoot "target\smoke_test"
if (Test-Path $tempDir) {
    Remove-Item -Recurse -Force $tempDir
}
New-Item -ItemType Directory -Path $tempDir | Out-Null

$testFile = Join-Path $tempDir "hello.txt"
$keyFile = Join-Path $tempDir "testkey.key"
$encFile = Join-Path $tempDir "hello.crbx"
$decFile = Join-Path $tempDir "hello_restored.txt"

# Write test content
"Hello, Cryptobox Java!" | Set-Content -Path $testFile -Encoding UTF8 -NoNewline

try {
    # Test 1: --help
    Write-Host "--- Test 1: --help ---" -ForegroundColor Yellow
    $helpOutput = java -jar $jarPath --help 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Help command failed with exit code $LASTEXITCODE"
    }
    if ($helpOutput -match "Usage" -and $helpOutput -match "Commands") {
        Write-Host "[PASS] --help works correctly" -ForegroundColor Green
    } else {
        throw "Help output missing expected content"
    }

    # Test 2: keygen
    Write-Host ""
    Write-Host "--- Test 2: keygen ---" -ForegroundColor Yellow
    $keygenOutput = java -jar $jarPath keygen --output $keyFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Key generation failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path $keyFile)) {
        throw "Key file was not created"
    }
    $keyContent = Get-Content $keyFile -Raw
    if ($keyContent.Trim().Length -eq 0) {
        throw "Key file is empty"
    }
    Write-Host "[PASS] Key generated successfully at $keyFile" -ForegroundColor Green

    # Test 3: encrypt
    Write-Host ""
    Write-Host "--- Test 3: encrypt ---" -ForegroundColor Yellow
    $encOutput = java -jar $jarPath encrypt --key $keyFile --input $testFile --output $encFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Encryption failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path $encFile)) {
        throw "Encrypted file was not created"
    }
    Write-Host "[PASS] File encrypted successfully at $encFile" -ForegroundColor Green

    # Test 4: decrypt
    Write-Host ""
    Write-Host "--- Test 4: decrypt ---" -ForegroundColor Yellow
    $decOutput = java -jar $jarPath decrypt --key $keyFile --input $encFile --output $decFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Decryption failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path $decFile)) {
        throw "Decrypted file was not created"
    }
    $decContent = Get-Content $decFile -Raw -Encoding UTF8
    $expectedContent = "Hello, Cryptobox Java!"
    if ($decContent.Trim() -ne $expectedContent) {
        throw "Decrypted content mismatch. Expected '$expectedContent', got '$decContent'"
    }
    Write-Host "[PASS] File decrypted successfully, content matches" -ForegroundColor Green

    # Test 5: hash
    Write-Host ""
    Write-Host "--- Test 5: hash ---" -ForegroundColor Yellow
    $hashOutput = java -jar $jarPath hash --input $testFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Hash command failed with exit code $LASTEXITCODE"
    }
    if ($hashOutput -notmatch "[A-F0-9]{64}") {
        throw "Hash output does not contain a valid SHA256 hex string"
    }
    Write-Host "[PASS] Hash command works correctly" -ForegroundColor Green

    # Test 6: verify (uses --key to verify tag)
    Write-Host ""
    Write-Host "--- Test 6: verify ---" -ForegroundColor Yellow
    $verifyOutput = java -jar $jarPath verify --input $encFile --key $keyFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Verify command failed with exit code $LASTEXITCODE"
    }
    Write-Host "[PASS] Container verification passed" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== All smoke tests passed! ===" -ForegroundColor Green
    exit 0

} catch {
    Write-Host ""
    Write-Host "[FAIL] Smoke test failed: $_" -ForegroundColor Red
    exit 1

} finally {
    # Cleanup temp directory
    if (Test-Path $tempDir) {
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    }
}