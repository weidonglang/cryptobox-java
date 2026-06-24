# Developer Guide

## Overview

Cryptobox Java is a local file encryption CLI tool built with Java 17+ and Maven. It uses AES-256-GCM for authenticated encryption with Argon2id/PBKDF2 key derivation.

## Project Structure

```
cryptobox-java/
  src/main/java/com/cryptobox/
    Cryptobox.java          # Main entry point
    Cli.java                # picocli command definitions
    Config.java             # Configuration constants
    Errors.java             # Custom exception hierarchy
    ContainerParser.java    # Container format serialization/deserialization
    KeyDerivation.java      # Argon2id / PBKDF2 implementation
    CryptoEngine.java       # AES-256-GCM encryption/decryption
    FileProcessor.java      # File and directory recursive processing
    Integrity.java          # SHA256 hash computation
  src/test/java/com/cryptobox/
    # Test classes
  scripts/                  # PowerShell validation scripts
  docs/                     # Documentation
  examples/                 # Example files
  testdata/                 # Test data (valid/invalid containers)
```

## Prerequisites

- JDK 17 or later
- Apache Maven 3.6+
- PowerShell 7+ (for scripts)

## Build & Test

```bash
# Build the project
mvn compile

# Run all tests
mvn test

# Full verification (compile + test + checks)
mvn verify

# Build executable JAR with dependencies
mvn clean package
```

## Running

```bash
# Show help
java -jar target/cryptobox.jar --help

# Generate a key
java -jar target/cryptobox.jar keygen --output mykey.key

# Encrypt a file
java -jar target/cryptobox.jar encrypt --key mykey.key --input hello.txt --output hello.crbx

# Decrypt a file
java -jar target/cryptobox.jar decrypt --key mykey.key --input hello.crbx --output restored.txt

# Verify a container
java -jar target/cryptobox.jar verify --input hello.crbx --key mykey.key

# Compute SHA256 hash
java -jar target/cryptobox.jar hash --input hello.txt
```

## Validation Scripts

All scripts are in the `scripts/` directory:

```bash
# Run all tests
powershell -ExecutionPolicy Bypass -File scripts/run_all_tests.ps1

# Check version consistency
powershell -ExecutionPolicy Bypass -File scripts/check_version.ps1

# Check no artifacts tracked
powershell -ExecutionPolicy Bypass -File scripts/check_no_artifacts.ps1

# Check no network code
powershell -ExecutionPolicy Bypass -File scripts/check_no_network_code.ps1

# Count lines
powershell -ExecutionPolicy Bypass -File scripts/count_lines.ps1

# Build release
powershell -ExecutionPolicy Bypass -File scripts/build_release.ps1

# Package release
powershell -ExecutionPolicy Bypass -File scripts/package_release.ps1

# Smoke test
powershell -ExecutionPolicy Bypass -File scripts/smoke_test.ps1
```

## Architecture

### Encryption Pipeline

1. **Key Derivation**: Derive 256-bit key from password or load from key file
2. **Container Construction**: Build CRBX container with magic, version, salt, IV, ciphertext, tag
3. **AES-256-GCM Encryption**: Encrypt plaintext with random 12-byte IV
4. **File Output**: Write container to .crbx file

### Decryption Pipeline

1. **Container Parsing**: Parse and validate container format
2. **Key Loading**: Load key from file or derive from password
3. **AES-256-GCM Decryption**: Decrypt and verify GCM authentication tag
4. **File Output**: Write decrypted data to output file

### Container Format

The Cryptobox Container v1 format is binary:

| Field            | Size     |
|------------------|----------|
| Magic "CRBX"     | 4 bytes  |
| Version (0x0001) | 2 bytes  |
| Algorithm ID     | 2 bytes  |
| KDF ID           | 2 bytes  |
| Salt Length      | 2 bytes  |
| Salt             | Variable |
| IV Length        | 2 bytes  |
| IV               | Variable |
| Ciphertext Length| 4 bytes  |
| Ciphertext + Tag | Variable |

See [container_format.md](container_format.md) for full details.

## Security Requirements

- No network connections of any kind
- Keys/passwords cleared from memory immediately after use
- No weak encryption algorithms (DES, RC4, ECB)
- Container format validation before decryption
- GCM authentication tag verification

## How to Contribute

1. Create an issue describing the change
2. Branch from latest main: `git checkout -b task-N-short-name`
3. Implement changes, keeping to allowed files
4. Run validation: `powershell -File scripts/run_all_tests.ps1`
5. Commit with format: `Task N: summary`
6. Create PR with `Closes #ISSUE_NUMBER`
7. Ensure PR has exactly 1 commit