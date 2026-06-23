# Cryptobox Java

**Version: 1.0.0**

A local file encryption CLI tool using AES-256-GCM with Argon2id/PBKDF2 key derivation, supporting directory recursion and integrity verification. Designed for offline personal data protection.

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

## License

MIT License - see [LICENSE](LICENSE) for details.