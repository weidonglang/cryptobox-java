# Security Boundaries

## Enforcement Rules

This document defines the security boundaries that **must** be enforced throughout the Cryptobox Java project.

### Allowed Operations

1. Use standard symmetric encryption (AES-256-GCM)
2. Derive keys from passwords (Argon2id / PBKDF2)
3. Read and write local files
4. Recursively process directories
5. Generate random keys and save them to local files
6. Verify ciphertext integrity (GCM MAC check)
7. Container format defined as standard container format (salt, iv, ciphertext, tag)
8. Compute and record SHA256 checksums before and after encryption (local only)

### Strictly Prohibited Operations

1. **No network communication** of any kind:
   - No uploading keys, passwords, or ciphertext to any network
   - No downloading from any network
   - No time synchronization
   - No update checks
   - No DNS lookups

2. **No backdoor keys**: Never save unencrypted keys to plaintext logs

3. **No decrypting non-Cryptobox format files**

4. **No retaining passwords in memory**: Clear `char[]` immediately after use

5. **No weak encryption algorithms**:
   - DES is forbidden
   - RC4 is forbidden
   - ECB mode is forbidden

6. **No network API usage**: The following Java classes are forbidden:
   - `java.net.Socket`
   - `java.net.URL`
   - `java.net.HttpURLConnection`
   - `java.net.http.HttpClient`
   - `org.apache.http.*`
   - `okhttp3.*`

### Verification

Before each commit, run:

```bash
grep -rE "java\.net\.Socket|java\.net\.URL|java\.net\.HttpURLConnection|java\.net\.http\.HttpClient|org\.apache\.http|okhttp" --include="*.java" src test || true
```

If any matches are found, the offending code must be removed immediately.

### Memory Security

- All key material (`byte[]`) must be overwritten with zeros after use
- All password material (`char[]`) must be overwritten with null characters (`\0`) after use
- Use `java.util.Arrays.fill()` for clearing arrays
- Never log or print key material or passwords

### Container Format Security

- Container format includes authentication tag (GCM) for integrity verification
- Container format validation checks magic bytes, version, and length fields
- Decryption fails with a generic message: "Decryption failed: wrong key or corrupted data"
- Error messages must never reveal whether the key was wrong or the data was corrupted