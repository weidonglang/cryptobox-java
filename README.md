# Cryptobox Java

**Version: 1.0.0**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-blue)](https://adoptium.net/)
[![Maven](https://img.shields.io/badge/Maven-3.8%2B-red)](https://maven.apache.org/)

Cryptobox Java is a **local file encryption and decryption CLI tool** using AES-256-GCM authenticated encryption with Argon2id/PBKDF2 key derivation. It supports directory recursion, integrity verification, and a standardized container format — designed for **offline personal data protection** with zero network dependencies.

## Project Overview

| Attribute | Value |
|-----------|-------|
| **Project** | cryptobox-java |
| **Version** | 1.0.0 |
| **Language** | Java 17+ |
| **Build** | Maven |
| **Encryption** | AES-256-GCM |
| **Key Derivation** | Argon2id / PBKDF2 |
| **License** | MIT |
| **Security** | Zero network connections, memory cleanup |

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Security](#security)
- [Container Format](#container-format)
- [Build](#build)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [License](#license)

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** and **PBKDF2** key derivation
- **Key file** or **password** based encryption
- **Directory recursive** encryption and decryption
- **Container format** integrity verification
- **SHA256** file hashing
- **Cross-platform** (Java 17+)

## Quick Start

```bash
# Build
mvn clean package

# Generate a key
java -jar target/cryptobox.jar keygen --output mykey.key

# Encrypt a file
java -jar target/cryptobox.jar encrypt --key mykey.key --input hello.txt --output hello.crbx

# Decrypt a file
java -jar target/cryptobox.jar decrypt --key mykey.key --input hello.crbx --output hello_restored.txt

# Verify a container
java -jar target/cryptobox.jar verify --input hello.crbx --key mykey.key

# Compute SHA256
java -jar target/cryptobox.jar hash --input hello.txt
```

## Security

- No network connections are ever made
- Keys and passwords are cleared from memory immediately after use
- Uses AES-256-GCM with random IVs
- Container format includes integrity verification (GCM authentication tag)
- See [Security Boundaries](docs/security_boundaries.md) for full details

## Commands

| Command   | Description                                      |
|-----------|--------------------------------------------------|
| `keygen`  | Generate a random 32-byte AES-256 key file       |
| `encrypt` | Encrypt a file or directory                      |
| `decrypt` | Decrypt a Cryptobox container                    |
| `verify`  | Verify container format and integrity            |
| `hash`    | Compute SHA256 hash of a file or directory       |

## Container Format

Cryptobox uses a custom binary container format:

```
Magic:       4 bytes "CRBX"
Version:     2 bytes (0x0001)
Algorithm:   2 bytes (0x01 = AES-256-GCM)
KDF ID:      2 bytes (0x01=Argon2id, 0x02=PBKDF2)
Salt length: 2 bytes (uint16 big-endian)
Salt:        <Salt length> bytes
IV length:   2 bytes (uint16 big-endian)
IV:          <IV length> bytes
Ciphertext:  4 bytes (uint32 big-endian) length
Ciphertext:  ciphertext + 16-byte GCM tag
```

See [Container Format](docs/container_format.md) for full specification.

## Build

```bash
mvn clean package
java -jar target/cryptobox.jar --help
```

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
    CliHelpTest.java        # CLI help and command tests
    ContainerTest.java      # Container format tests
    KeyDerivationTest.java  # Key derivation tests
    CryptoEngineTest.java   # Encryption engine tests
    FileProcessorTest.java  # File processing tests
    IntegrityTest.java      # SHA256 hash tests
    EdgeCaseTest.java       # Edge case and error handling tests
  scripts/                  # PowerShell validation scripts
  docs/                     # Documentation
  examples/                 # Example files for testing
  testdata/                 # Pre-generated test containers
  dist/                     # Release packages (not committed)
```

## Documentation

| Document | Description |
|----------|-------------|
| [User Guide](docs/user_guide.md) | Complete CLI command reference with examples |
| [Developer Guide](docs/developer_guide.md) | Architecture, build, and contribution guide |
| [Container Format](docs/container_format.md) | Binary container format specification |
| [Security Boundaries](docs/security_boundaries.md) | Security requirements and constraints |
| [Release Notes](docs/release_notes.md) | Version history and changelog |

## License

MIT License - see [LICENSE](LICENSE) for details.
