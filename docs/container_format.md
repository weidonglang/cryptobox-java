# Cryptobox Container Format v1

## Overview

Encrypted output files use a custom binary container format `Cryptobox Container v1`.
This format encapsulates all metadata required for decryption (salt, IV, algorithm parameters)
along with the ciphertext and GCM authentication tag.

All modules, tests, and documentation must strictly follow this format specification.

## Binary Layout

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Magic | Magic bytes: `CRBX` (0x43 0x52 0x42 0x58) |
| 4 | 2 | Version | Container version: 0x0001 |
| 6 | 2 | Algorithm ID | Encryption algorithm: 0x0001 = AES-256-GCM |
| 8 | 2 | KDF ID | Key derivation function: 0x0001 = Argon2id, 0x0002 = PBKDF2 |
| 10 | 2 | Salt Length | Salt length in bytes (uint16 big-endian) |
| 12 | N | Salt | Salt bytes (typically 16) |
| 12+N | 2 | IV Length | IV length in bytes (uint16 big-endian) |
| 14+N | M | IV | Initialization vector bytes (typically 12) |
| 14+N+M | 4 | Ciphertext Length | Ciphertext length in bytes (uint32 big-endian) |
| 18+N+M | L | Ciphertext | Ciphertext + 16-byte GCM tag |

### Field Details

**Magic (4 bytes)**
- Fixed value: 0x43 0x52 0x42 0x58 (ASCII "CRBX")
- Used to identify Cryptobox container files
- Files without valid magic are rejected immediately

**Version (2 bytes)**
- Current version: 0x0001
- Big-endian unsigned short
- Future versions may extend the format

**Algorithm ID (2 bytes)**
- 0x0001: AES-256-GCM (only supported algorithm)
- Big-endian unsigned short

**KDF ID (2 bytes)**
- 0x0001: Argon2id
- 0x0002: PBKDF2WithHmacSHA512
- Big-endian unsigned short

**Salt Length (2 bytes)**
- Length of the salt field in bytes
- Big-endian unsigned short
- Typically 16

**Salt (variable)**
- Random salt for key derivation
- Read length from Salt Length field
- Must be at least 8 bytes, maximum 64 bytes

**IV Length (2 bytes)**
- Length of the IV field in bytes
- Big-endian unsigned short
- Typically 12 for GCM

**IV (variable)**
- Random initialization vector
- Read length from IV Length field
- Must be 12 bytes for AES-256-GCM

**Ciphertext Length (4 bytes)**
- Total length of ciphertext including GCM tag
- Big-endian unsigned int
- Includes the 16-byte GCM authentication tag at the end

**Ciphertext (variable)**
- Actual ciphertext bytes
- Last 16 bytes are the GCM authentication tag (128 bits)

## Validation Rules

A container is valid only if ALL of the following conditions are met:

1. First 4 bytes must equal `CRBX` (0x43 0x52 0x42 0x58)
2. Version must be 0x0001
3. Algorithm ID must be 0x0001
4. KDF ID must be 0x0001 or 0x0002
5. Salt length must be between 8 and 64 (inclusive)
6. Salt data must be present (length must match declared salt length)
7. IV length must be between 8 and 32 (inclusive)
8. IV data must be present
9. Ciphertext length must be positive
10. Ciphertext length must not exceed remaining data
11. Total data must exactly match expected sum of all fields
12. GCM tag validation requires the correct decryption key

## Example Hex Dump

```
Offset  Hex                                           ASCII
------  --------------------------------------------  ----
0000    43 52 42 58                                   CRBX
0004    00 01                                         ..
0006    00 01                                         ..
0008    00 01                                         ..
000A    00 10                                         ..
000C    5b c3 36 b9 91 47 60 cd 12 d3 a3 ce 13 88 2c b6  [.6..G`........,.
001C    00 0c                                           ..
001E    db 99 0a 30 a2 19 7c 45 b3 15 3d d6              ...0..|E..=.
002A    00 00 00 51                                      ...Q
002E    6f bd 95 c7 e6 6f 16 25 5b 9e ad 41 f5 67 17 3b  o....o.%[...A.g.;
...
```

## No Optional Fields

The Cryptobox Container v1 format has no optional fields.
All fields must be present in the exact order specified.