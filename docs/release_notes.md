# Release Notes

## v1.0.0 (2024-01-15)

Cryptobox Java v1.0.0 — Initial stable release of the local file encryption and decryption CLI tool.

### Features

- **Encryption & Decryption**: AES-256-GCM authenticated encryption with 128-bit GCM tag
- **Key Derivation**: 
  - Argon2id (memory: 64MB, iterations: 3, parallelism: 4)
  - PBKDF2WithHmacSHA512 (600,000 iterations) as fallback
- **Key Management**: Random 256-bit key generation with Base64 file storage
- **Password Support**: Interactive password input via Console.readPassword()
- **Container Format**: Standardized Cryptobox Container v1 format
- **Directory Recursion**: Encrypt/decrypt entire directory trees with TAR-like bundling
- **Integrity Verification**: 
  - Container structure and MAC verification
  - SHA-256 file hashing for integrity checks
- **CLI Commands**: encrypt, decrypt, keygen, verify, hash, help

### Security

- No network communication capabilities
- Memory cleanup of sensitive data after use
- Strong algorithms only (AES-256-GCM, Argon2id)
- Secure container format with magic bytes and versioning
- Full test coverage for edge cases and attack vectors

### Packaging

- Fat JAR with all dependencies (cryptobox.jar)
- Release ZIP archive containing JAR, docs, examples, and scripts
- MIT License

### Documentation

- User guide covering all CLI commands
- Developer guide with architecture overview
- Container format specification
- Security boundaries document
- API reference documentation

### Requirements

- Java 17 or higher
- Maven 3.8+ (for building from source)

### Known Issues

- None