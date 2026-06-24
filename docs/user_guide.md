# Cryptobox Java User Guide

## Overview

Cryptobox Java is a local file encryption and decryption command-line tool using AES-256-GCM authenticated encryption. It supports key derivation (Argon2id / PBKDF2), integrity verification, recursive directory encryption/decryption, and container format validation.

## Installation

### Prerequisites

- Java 17 or later
- Maven 3.8+

### Building from Source

```bash
git clone https://github.com/weidonglang/cryptobox-java.git
cd cryptobox-java
mvn clean package -DskipTests
```

The executable JAR will be at `target/cryptobox.jar`.

## Quick Start

### 1. Generate a Key

```bash
java -jar cryptobox.jar keygen --output mykey.key
```

### 2. Encrypt a File

```bash
java -jar cryptobox.jar encrypt --key mykey.key --input hello.txt --output hello.crbx
```

### 3. Decrypt a File

```bash
java -jar cryptobox.jar decrypt --key mykey.key --input hello.crbx --output hello_restored.txt
```

### 4. Verify a Container

```bash
java -jar cryptobox.jar verify --input hello.crbx
java -jar cryptobox.jar verify --input hello.crbx --key mykey.key
```

### 5. Compute SHA256 Hash

```bash
java -jar cryptobox.jar hash --input hello.txt
java -jar cryptobox.jar hash --input docs/ --algorithm SHA256
```

## Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--help` | Display help information |
| `--version` | Display version information |

### `keygen` — Generate Encryption Key

Generates a random 32-byte AES-256 key and saves it as Base64-encoded text.

**Usage:**
```bash
java -jar cryptobox.jar keygen --output <file>
```

**Options:**
| Option | Description |
|--------|-------------|
| `-o, --output` | Output key file path (required) |

**Example:**
```bash
java -jar cryptobox.jar keygen --output mykey.key
```

### `encrypt` — Encrypt Files

Encrypts a file or directory using AES-256-GCM. Supports both key-file and password-based encryption.

**Usage:**
```bash
java -jar cryptobox.jar encrypt --key <keyfile> --input <file/dir> --output <container>
java -jar cryptobox.jar encrypt --password --input <file/dir> --output <container>
```

**Options:**
| Option | Description |
|--------|-------------|
| `-k, --key` | Path to the encryption key file |
| `-p, --password` | Use password-based encryption (interactive prompt) |
| `-i, --input` | Input file or directory path (required) |
| `-o, --output` | Output container file path (required) |
| `-r, --recursive` | Encrypt directory recursively |
| `--exclude` | Exclude files matching pattern (comma-separated) |

**Notes:**
- Either `--key` or `--password` must be specified (not both).
- Password is entered via secure console input (no echo).
- Password must be confirmed by entering twice.
- For directories, `--recursive` is required.

**Examples:**

Encrypt with key file:
```bash
java -jar cryptobox.jar encrypt --key mykey.key --input document.pdf --output document.crbx
```

Encrypt with password:
```bash
java -jar cryptobox.jar encrypt --password --input photo.jpg --output photo.crbx
```

Encrypt directory recursively:
```bash
java -jar cryptobox.jar encrypt --key mykey.key --recursive --path ./docs/ --output docs-archive.crbx --exclude .git,tmp
```

### `decrypt` — Decrypt Files

Decrypts a Cryptobox container file back to the original file.

**Usage:**
```bash
java -jar cryptobox.jar decrypt --key <keyfile> --input <container> --output <file>
java -jar cryptobox.jar decrypt --password --input <container> --output <file>
```

**Options:**
| Option | Description |
|--------|-------------|
| `-k, --key` | Path to the decryption key file |
| `-p, --password` | Use password-based decryption (interactive prompt) |
| `-i, --input` | Input container file (required) |
| `-o, --output` | Output file path (required) |

**Notes:**
- Either `--key` or `--password` must be specified (not both).
- Automatic container format validation is performed before decryption.
- On failure, a generic message "Decryption failed: wrong key or corrupted data" is shown (key material is never leaked).

**Examples:**

Decrypt with key file:
```bash
java -jar cryptobox.jar decrypt --key mykey.key --input document.crbx --output document_restored.pdf
```

Decrypt with password:
```bash
java -jar cryptobox.jar decrypt --password --input photo.crbx --output photo_restored.jpg
```

### `verify` — Verify Container Integrity

Validates a Cryptobox container file's format and optionally checks the GCM authentication tag.

**Usage:**
```bash
java -jar cryptobox.jar verify --input <container>
java -jar cryptobox.jar verify --input <container> --key <keyfile>
```

**Options:**
| Option | Description |
|--------|-------------|
| `-i, --input` | Input container file (required) |
| `-k, --key` | Key file for GCM tag verification (optional) |

**Verification checks (format only):**
- Magic bytes: must be "CRBX"
- Version: must be 0x0001
- Salt length: must be positive and ≤ 64
- IV length: must be positive and ≤ 32
- Ciphertext length: must be positive and within bounds

**With key (full integrity check):**
- In addition to format checks, the GCM authentication tag is verified.
- This confirms the ciphertext has not been tampered with.
- The key is required because tag verification requires decryption.

**Examples:**

Basic format verification:
```bash
java -jar cryptobox.jar verify --input document.crbx
```

Full integrity verification:
```bash
java -jar cryptobox.jar verify --input document.crbx --key mykey.key
```

**Exit codes:**
- `0`: Container is valid
- `1`: Verification failed (invalid format, corrupted data, or wrong key)

### `hash` — Compute File Hash

Computes the SHA256 hash of a file or directory.

**Usage:**
```bash
java -jar cryptobox.jar hash --input <file>
java -jar cryptobox.jar hash --input <directory> --algorithm SHA256
```

**Options:**
| Option | Description |
|--------|-------------|
| `-i, --input` | Input file or directory path (required) |
| `-a, --algorithm` | Hash algorithm (default: SHA256, currently only SHA256 supported) |

**Examples:**

Hash a single file:
```bash
java -jar cryptobox.jar hash --input document.pdf
```

Hash all files in a directory:
```bash
java -jar cryptobox.jar hash --input ./docs/
```

**Output format:**
- Single file: `<hash>  <filename>`
- Directory: one line per file, with relative path: `<hash>  <relative_path>`

## Security Notes

1. **Local only**: This tool performs all operations locally. No network connections are made.
2. **Key security**: Key files should be stored securely and never shared.
3. **Password security**: Passwords are entered via secure console input (no echo) and cleared from memory immediately after key derivation.
4. **Algorithm**: AES-256-GCM provides authenticated encryption (confidentiality + integrity).
5. **Memory safety**: Keys and passwords are zeroed out after use.
6. **Container format**: The `.crbx` container includes salt, IV, and ciphertext with GCM tag.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (see error message for details) |

## Troubleshooting

### "Input file not found"
Verify the file path exists and is readable.

### "Decryption failed: wrong key or corrupted data"
The key or password is incorrect, or the container file has been corrupted.

### "Not a valid Cryptobox container"
The input file is not a valid `.crbx` container. Verify you're decrypting a Cryptobox container.

### "No console available"
The tool cannot read password input. Try running in an interactive terminal.