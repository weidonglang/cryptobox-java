# Cryptobox Java Examples

This directory contains sample files for testing Cryptobox Java encryption/decryption.

## Files

### hello.txt
Simple text file with a greeting message. Used for basic encryption/decryption testing.

### config.json
A sample JSON configuration file representing structured data. Tests encryption of non-text binary-like content (UTF-8 JSON).

### lena.png
A 1x1 pixel placeholder PNG image. Represents binary file encryption testing.

### test_dir/
A nested directory structure for testing recursive directory encryption:
- `a.txt` - First file in directory
- `b.txt` - Second file in directory
- `sub/c.txt` - File in subdirectory (tests deep nesting)

## Usage Examples

Encrypt a single file:
```bash
java -jar cryptobox.jar encrypt --key mykey.key --input examples/hello.txt --output hello.crbx
```

Encrypt with password:
```bash
java -jar cryptobox.jar encrypt --password --input examples/config.json --output config.crbx
```

Encrypt an entire directory recursively:
```bash
java -jar cryptobox.jar encrypt --key mykey.key --recursive --path examples/test_dir/ --output test_dir.crbx
```

Decrypt a file:
```bash
java -jar cryptobox.jar decrypt --key mykey.key --input hello.crbx --output hello_restored.txt
```

Verify a container:
```bash
java -jar cryptobox.jar verify --key mykey.key --input hello.crbx
```

## Notes

- All files in this directory are safe to commit
- Do not commit any `.crbx` files generated from these examples
- The lena.png is a minimal valid PNG file (67 bytes)