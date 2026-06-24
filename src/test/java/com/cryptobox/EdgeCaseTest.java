package com.cryptobox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Edge case tests for error handling and boundary conditions.
 * <p>
 * Tests file not found, permission denied simulation, empty files,
 * invalid key files, and other error scenarios.
 * </p>
 */
public class EdgeCaseTest {

    @TempDir
    Path tempDir;

    // -------- Container Format Edge Cases --------

    @Test
    public void testCorruptedContainerBadMagic() {
        byte[] data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02,
                       0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        assertThrows(Errors.ContainerFormatException.class, () -> ContainerParser.parse(data),
                "Should reject container with bad magic bytes");
    }

    @Test
    public void testCorruptedContainerWrongVersion() {
        byte[] data = {0x43, 0x52, 0x42, 0x58, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
                       0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        assertThrows(Errors.ContainerFormatException.class, () -> ContainerParser.parse(data),
                "Should reject container with unsupported version");
    }

    @Test
    public void testTruncatedContainer() {
        // Only magic bytes, no version
        byte[] data = {0x43, 0x52, 0x42, 0x58};
        assertThrows(Errors.ContainerFormatException.class, () -> ContainerParser.parse(data),
                "Should reject truncated container");
    }

    @Test
    public void testEmptyContainer() {
        byte[] data = new byte[0];
        assertThrows(Errors.ContainerFormatException.class, () -> ContainerParser.parse(data),
                "Should reject empty container data");
    }

    @Test
    public void testNullContainer() {
        assertThrows(Errors.ContainerFormatException.class, () -> ContainerParser.parse(null),
                "Should reject null container data");
    }

    @Test
    public void testContainerWithMissingFields() {
        // Has magic and version but missing algorithm and KDF fields
        byte[] data = {0x43, 0x52, 0x42, 0x58, 0x00, 0x01, 0x00, 0x01};
        assertThrows(Errors.ContainerFormatException.class, () -> ContainerParser.parse(data),
                "Should reject container with missing fields");
    }

    @Test
    public void testContainerWithInvalidSaltLength() {
        // Set salt length to an impossibly large value
        byte[] data = {0x43, 0x52, 0x42, 0x58, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02,
                       0x7F, (byte) 0xFF, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        assertThrows(Errors.ContainerFormatException.class, () -> ContainerParser.parse(data),
                "Should reject container with invalid salt length");
    }

    // -------- Key File Edge Cases --------

    @Test
    public void testKeyFileNotFound() {
        Path nonExistent = tempDir.resolve("nonexistent.key");
        assertThrows(Errors.FileOperationException.class, () ->
                Cli.loadKeyFromFile(nonExistent.toString()),
                "Should throw FileOperationException for non-existent key file");
    }

    @Test
    public void testKeyFileEmpty() throws IOException {
        Path emptyKey = tempDir.resolve("empty.key");
        Files.writeString(emptyKey, "");
        assertThrows(Errors.FileOperationException.class, () ->
                Cli.loadKeyFromFile(emptyKey.toString()),
                "Should throw FileOperationException for empty key file");
    }

    @Test
    public void testKeyFileInvalidBase64() throws IOException {
        Path invalidKey = tempDir.resolve("invalid.key");
        Files.writeString(invalidKey, "not-base64-content!!!");
        assertThrows(Errors.FileOperationException.class, () ->
                Cli.loadKeyFromFile(invalidKey.toString()),
                "Should throw FileOperationException for invalid Base64 key file");
    }

    @Test
    public void testKeyFileWrongLength() throws IOException {
        Path wrongLenKey = tempDir.resolve("wronglen.key");
        // 16 bytes encoded is not 32 bytes
        byte[] shortKey = new byte[16];
        new java.security.SecureRandom().nextBytes(shortKey);
        String encoded = Base64.getEncoder().encodeToString(shortKey);
        Files.writeString(wrongLenKey, encoded);
        assertThrows(Errors.KeyDerivationException.class, () ->
                KeyDerivation.decodeKeyFromBase64(encoded),
                "Should reject decoded key with wrong length");
    }

    @Test
    public void testKeyFileWithWhitespace() throws IOException {
        Path keyFile = tempDir.resolve("key-with-whitespace.key");
        byte[] key = CryptoEngine.generateKey();
        String encoded = Base64.getEncoder().encodeToString(key);
        Files.writeString(keyFile, "  " + encoded + "\n  \n");
        byte[] loadedKey = Cli.loadKeyFromFile(keyFile.toString());
        assertArrayEquals(key, loadedKey, "Key with surrounding whitespace should load correctly");
    }

    @Test
    public void testKeyFileWithCommentsLines() throws IOException {
        Path keyFile = tempDir.resolve("key-with-comments.key");
        byte[] key = CryptoEngine.generateKey();
        String encoded = Base64.getEncoder().encodeToString(key);
        Files.writeString(keyFile, "# This is a comment line\n# Key version: 1.0\n" + encoded + "\n");
        byte[] loadedKey = Cli.loadKeyFromFile(keyFile.toString());
        assertArrayEquals(key, loadedKey, "Key file with comments should load correctly");
    }

    // -------- Crypto Engine Edge Cases --------

    @Test
    public void testEncryptEmptyPlaintext() {
        byte[] empty = new byte[0];
        byte[] key = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();
        byte[] ciphertext = CryptoEngine.encrypt(empty, key, iv);
        assertNotNull(ciphertext, "Ciphertext should not be null even for empty plaintext");
        assertTrue(ciphertext.length >= Config.GCM_TAG_SIZE,
                "Ciphertext should at least contain GCM tag");
    }

    @Test
    public void testEncryptDecryptOneByte() {
        byte[] data = {(byte) 0xFF};
        byte[] key = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();
        byte[] ciphertext = CryptoEngine.encrypt(data, key, iv);
        byte[] decrypted = CryptoEngine.decrypt(ciphertext, key, iv);
        assertArrayEquals(data, decrypted, "Single byte should round-trip correctly");
    }

    @Test
    public void testEncryptDecryptLargeData() {
        // 1 MB of random data
        byte[] data = new byte[1024 * 1024];
        new java.security.SecureRandom().nextBytes(data);
        byte[] key = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();
        byte[] ciphertext = CryptoEngine.encrypt(data, key, iv);
        byte[] decrypted = CryptoEngine.decrypt(ciphertext, key, iv);
        assertArrayEquals(data, decrypted, "1 MB data should round-trip correctly");
    }

    @Test
    public void testEncryptDecryptAllByteValues() {
        // Test all possible byte values 0x00-0xFF
        byte[] data = new byte[256];
        for (int i = 0; i < 256; i++) {
            data[i] = (byte) i;
        }
        byte[] key = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();
        byte[] ciphertext = CryptoEngine.encrypt(data, key, iv);
        byte[] decrypted = CryptoEngine.decrypt(ciphertext, key, iv);
        assertArrayEquals(data, decrypted, "All byte values should round-trip correctly");
    }

    @Test
    public void testDecryptWithWrongKey() {
        byte[] plaintext = "Hello World".getBytes();
        byte[] key1 = CryptoEngine.generateKey();
        byte[] key2 = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, key1, iv);
        assertThrows(Errors.DecryptionException.class, () ->
                        CryptoEngine.decrypt(ciphertext, key2, iv),
                "Decryption with wrong key should throw DecryptionException");
    }

    @Test
    public void testDecryptWithWrongIv() {
        byte[] plaintext = "Test data".getBytes();
        byte[] key = CryptoEngine.generateKey();
        byte[] iv1 = CryptoEngine.generateIv();
        byte[] iv2 = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, key, iv1);
        assertThrows(Errors.DecryptionException.class, () ->
                        CryptoEngine.decrypt(ciphertext, key, iv2),
                "Decryption with wrong IV should throw DecryptionException");
    }

    @Test
    public void testDecryptCorruptedCiphertext() {
        byte[] plaintext = "Sensitive data".getBytes();
        byte[] key = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, key, iv);
        // Corrupt one byte in the ciphertext
        ciphertext[5] ^= 0xFF;

        assertThrows(Errors.DecryptionException.class, () ->
                        CryptoEngine.decrypt(ciphertext, key, iv),
                "Decryption of corrupted ciphertext should throw DecryptionException");
    }

    @Test
    public void testDecryptCorruptedGcmTag() {
        byte[] plaintext = "Important data".getBytes();
        byte[] key = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, key, iv);
        // Corrupt the last byte (part of GCM tag)
        ciphertext[ciphertext.length - 1] ^= 0x01;

        assertThrows(Errors.DecryptionException.class, () ->
                        CryptoEngine.decrypt(ciphertext, key, iv),
                "Decryption with corrupted GCM tag should throw DecryptionException");
    }

    @Test
    public void testInvalidKeySize() {
        byte[] invalidKey = new byte[16]; // 128-bit, not 256-bit
        byte[] iv = CryptoEngine.generateIv();
        assertThrows(Errors.CryptoException.class, () ->
                        CryptoEngine.encrypt("data".getBytes(), invalidKey, iv),
                "Encryption with wrong key size should throw CryptoException");
    }

    @Test
    public void testInvalidIvSize() {
        byte[] key = CryptoEngine.generateKey();
        byte[] invalidIv = new byte[8]; // 64-bit, should be 96-bit
        assertThrows(Errors.CryptoException.class, () ->
                        CryptoEngine.encrypt("data".getBytes(), key, invalidIv),
                "Encryption with wrong IV size should throw CryptoException");
    }

    @Test
    public void testNullPlaintext() {
        byte[] key = CryptoEngine.generateKey();
        byte[] iv = CryptoEngine.generateIv();
        assertThrows(Errors.CryptoException.class, () ->
                        CryptoEngine.encrypt(null, key, iv),
                "Encryption with null plaintext should throw CryptoException");
    }

    @Test
    public void testNullKey() {
        byte[] iv = CryptoEngine.generateIv();
        assertThrows(Errors.CryptoException.class, () ->
                        CryptoEngine.encrypt("data".getBytes(), null, iv),
                "Encryption with null key should throw CryptoException");
    }

    // -------- Integrity Edge Cases --------

    @Test
    public void testHashEmptyFile() throws IOException {
        Path emptyFile = tempDir.resolve("empty.txt");
        Files.createFile(emptyFile);
        String hash = Integrity.computeHash(emptyFile);
        // SHA256 of empty string
        assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                hash, "SHA256 of empty file should match known value");
    }

    @Test
    public void testHashByteArrayConsistency() {
        byte[] data = "Consistent test data".getBytes();
        String hash1 = Integrity.computeHash(data);
        String hash2 = Integrity.computeHash(data);
        assertEquals(hash1, hash2, "Hash of same data should be identical");
    }

    @Test
    public void testHashLargeDataConsistency() {
        byte[] data = new byte[100000];
        new java.security.SecureRandom().nextBytes(data);
        String hash1 = Integrity.computeHash(data);
        String hash2 = Integrity.computeHash(data);
        assertEquals(hash1, hash2, "Hash of same large data should be identical");
    }

    @Test
    public void testDifferentDataDifferentHash() {
        byte[] data1 = "Data A".getBytes();
        byte[] data2 = "Data B".getBytes();
        String hash1 = Integrity.computeHash(data1);
        String hash2 = Integrity.computeHash(data2);
        assertNotEquals(hash1, hash2, "Different data should produce different hashes");
    }

    @Test
    public void testHashNullData() {
        assertThrows(Errors.CryptoException.class, () ->
                Integrity.computeHash((byte[]) null),
                "Hashing null data should throw CryptoException");
    }

    @Test
    public void testHashFormat() {
        byte[] data = "test".getBytes();
        String hash = Integrity.computeHash(data);
        // SHA256 hex string should be 64 characters, all uppercase hex
        assertEquals(64, hash.length(), "SHA256 hex string should be 64 chars");
        assertTrue(hash.matches("[0-9A-F]{64}"), "SHA256 hex should be uppercase hex only");
    }

    // -------- Key Derivation Edge Cases --------

    @Test
    public void testKeyDerivationConsistency() {
        byte[] salt = KeyDerivation.generateSalt();
        char[] password1 = "testPassword123!@#".toCharArray();
        byte[] key1 = KeyDerivation.deriveKeyFromPassword(password1, salt);
        // Password1 is now cleared, create a fresh copy for second derivation
        char[] password2 = "testPassword123!@#".toCharArray();
        byte[] key2 = KeyDerivation.deriveKeyFromPassword(password2, salt);

        assertArrayEquals(key1, key2, "Same password and salt should produce same key");
    }

    @Test
    public void testDifferentPasswordDifferentKey() {
        byte[] salt = KeyDerivation.generateSalt();
        char[] password1 = "password1".toCharArray();
        char[] password2 = "password2".toCharArray();
        byte[] key1 = KeyDerivation.deriveKeyFromPassword(password1, salt);
        byte[] key2 = KeyDerivation.deriveKeyFromPassword(password2, salt);

        assertFalse(java.util.Arrays.equals(key1, key2),
                "Different passwords should produce different keys");
    }

    @Test
    public void testDifferentSaltDifferentKey() {
        byte[] salt1 = KeyDerivation.generateSalt();
        byte[] salt2 = KeyDerivation.generateSalt();
        char[] password1 = "samePassword".toCharArray();
        char[] password2 = "samePassword".toCharArray();
        byte[] key1 = KeyDerivation.deriveKeyFromPassword(password1, salt1);
        byte[] key2 = KeyDerivation.deriveKeyFromPassword(password2, salt2);

        assertFalse(java.util.Arrays.equals(key1, key2),
                "Different salts should produce different keys");
    }

    @Test
    public void testEmptyPassword() {
        byte[] salt = KeyDerivation.generateSalt();
        char[] emptyPassword = new char[0];
        byte[] key = KeyDerivation.deriveKeyFromPassword(emptyPassword, salt);
        assertNotNull(key, "Empty password should still produce a key");
        assertEquals(Config.KEY_SIZE, key.length, "Key from empty password should be 32 bytes");
    }

    @Test
    public void testNullPassword() {
        byte[] salt = KeyDerivation.generateSalt();
        assertThrows(Errors.KeyDerivationException.class, () ->
                KeyDerivation.deriveKeyFromPassword(null, salt),
                "Null password should throw KeyDerivationException");
    }

    @Test
    public void testNullSalt() {
        char[] password = "testPassword".toCharArray();
        assertThrows(Errors.KeyDerivationException.class, () ->
                KeyDerivation.deriveKeyFromPassword(password, null),
                "Null salt should throw KeyDerivationException");
    }

    @Test
    public void testKeyGeneration() {
        // Generate key manually
        byte[] key = CryptoEngine.generateKey();
        assertNotNull(key, "Generated key should not be null");
        assertEquals(32, key.length, "Generated key should be 32 bytes (256-bit)");
    }

    @Test
    public void testIvGeneration() {
        byte[] iv = CryptoEngine.generateIv();
        assertNotNull(iv, "Generated IV should not be null");
        assertEquals(12, iv.length, "Generated IV should be 12 bytes (96-bit)");
    }

    // -------- File Processing Edge Cases --------

    @Test
    public void testEncryptDecryptFileWithSpaces() throws IOException {
        Path inputDir = tempDir.resolve("test dir with spaces");
        Files.createDirectories(inputDir);
        Path inputFile = inputDir.resolve("my file.txt");
        Files.writeString(inputFile, "Content with spaces in path");

        Path outputFile = tempDir.resolve("output.crbx");
        Path restoredFile = tempDir.resolve("restored file.txt");

        byte[] key = CryptoEngine.generateKey();
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, outputFile, key);
        processor.decryptFile(outputFile, restoredFile, key);

        String restoredContent = Files.readString(restoredFile);
        assertEquals("Content with spaces in path", restoredContent,
                "File with spaces in path should round-trip correctly");
    }

    @Test
    public void testEncryptDecryptEmptyFile() throws IOException {
        Path inputFile = tempDir.resolve("empty.txt");
        Files.createFile(inputFile);

        Path outputFile = tempDir.resolve("empty.crbx");
        Path restoredFile = tempDir.resolve("restored_empty.txt");

        byte[] key = CryptoEngine.generateKey();
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, outputFile, key);
        processor.decryptFile(outputFile, restoredFile, key);

        assertEquals(0, Files.size(restoredFile),
                "Empty file should round-trip to empty file");
    }

    @Test
    public void testDecryptWithWrongKeyFile() throws IOException {
        Path inputFile = tempDir.resolve("original.txt");
        Files.writeString(inputFile, "Secret data");

        Path outputFile = tempDir.resolve("secret.crbx");
        Path restoredFile = tempDir.resolve("restored.txt");

        byte[] correctKey = CryptoEngine.generateKey();
        byte[] wrongKey = CryptoEngine.generateKey();

        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, outputFile, correctKey);

        assertThrows(Errors.DecryptionException.class, () ->
                        processor.decryptFile(outputFile, restoredFile, wrongKey),
                "Decryption with wrong key should throw DecryptionException");
    }

    @Test
    public void testEncryptNonexistentInput() {
        Path nonExistent = tempDir.resolve("nonexistent.txt");
        Path outputFile = tempDir.resolve("output.crbx");
        byte[] key = CryptoEngine.generateKey();

        FileProcessor processor = new FileProcessor();
        assertThrows(Errors.FileOperationException.class, () ->
                        processor.encryptFile(nonExistent, outputFile, key),
                "Encrypting non-existent file should throw FileOperationException");
    }

    @Test
    public void testDecryptNonexistentContainer() {
        Path nonExistent = tempDir.resolve("nonexistent.crbx");
        Path outputFile = tempDir.resolve("output.txt");
        byte[] key = CryptoEngine.generateKey();

        FileProcessor processor = new FileProcessor();
        assertThrows(Errors.FileOperationException.class, () ->
                        processor.decryptFile(nonExistent, outputFile, key),
                "Decrypting non-existent container should throw FileOperationException");
    }

    @Test
    public void testEncryptToDirectory() throws IOException {
        Path inputFile = tempDir.resolve("source.txt");
        Files.writeString(inputFile, "Test content");

        // Output to a non-existent subdirectory
        Path outputDir = tempDir.resolve("subdir/nested/output.crbx");

        byte[] key = CryptoEngine.generateKey();
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, outputDir, key);

        assertTrue(Files.exists(outputDir), "Output directory should be auto-created");
    }

    @Test
    public void testDecryptFromDirectory() throws IOException {
        Path inputFile = tempDir.resolve("source.txt");
        Files.writeString(inputFile, "Test content");

        Path outputFile = tempDir.resolve("encrypted.crbx");
        Path restoreDir = tempDir.resolve("restore/deep/file.txt");

        byte[] key = CryptoEngine.generateKey();
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, outputFile, key);
        processor.decryptFile(outputFile, restoreDir, key);

        assertTrue(Files.exists(restoreDir), "Restore directory should be auto-created");
        assertEquals("Test content", Files.readString(restoreDir));
    }

    // -------- Unicode Password Edge Cases --------

    @Test
    public void testKeyDerivationWithUnicodePassword() {
        // Chinese, Japanese, emoji, special chars
        char[] password = "密码パスワード🔐!@#$%^&*()".toCharArray();
        byte[] salt = KeyDerivation.generateSalt();
        byte[] key = KeyDerivation.deriveKeyFromPassword(password, salt);

        assertNotNull(key, "Key derived from Unicode password should not be null");
        assertEquals(Config.KEY_SIZE, key.length,
                "Key derived from Unicode password should be 32 bytes");
    }

    @Test
    public void testEncryptDecryptWithUnicodeFilename() throws IOException {
        Path inputFile = tempDir.resolve("文件_файл_文件.txt");
        Files.writeString(inputFile, "Unicode filename content");

        Path outputFile = tempDir.resolve("unicode.crbx");
        Path restoredFile = tempDir.resolve("恢复_恢复_restored.txt");

        byte[] key = CryptoEngine.generateKey();
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, outputFile, key);
        processor.decryptFile(outputFile, restoredFile, key);

        assertEquals("Unicode filename content", Files.readString(restoredFile),
                "Unicode filenames should round-trip correctly");
    }

    // -------- Container Serialization Edge Cases --------

    @Test
    public void testContainerBuildParseRoundtrip() {
        byte[] salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
        byte[] iv = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C};
        byte[] ciphertext = {0x20, 0x21, 0x22, 0x23, 0x24};
        byte[] kdfId = {0x00, 0x01}; // Argon2id

        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        assertNotNull(container, "Built container should not be null");

        ContainerParser.ContainerData parsed = ContainerParser.parse(container);
        assertNotNull(parsed, "Parsed container should not be null");
        assertArrayEquals(salt, parsed.salt, "Salt should match");
        assertArrayEquals(iv, parsed.iv, "IV should match");
        assertArrayEquals(ciphertext, parsed.ciphertext, "Ciphertext should match");
    }

    @Test
    public void testContainerBuildWithEmptyCiphertext() {
        byte[] salt = KeyDerivation.generateSalt();
        byte[] iv = CryptoEngine.generateIv();
        byte[] ciphertext = new byte[0];
        byte[] kdfId = {0x00, 0x01};

        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        ContainerParser.ContainerData parsed = ContainerParser.parse(container);
        assertEquals(0, parsed.ciphertext.length, "Empty ciphertext should round-trip");
    }

    @Test
    public void testContainerBuildWithMaxSizeValues() {
        // Test with 256-byte salt and 256-byte IV (max reasonable)
        byte[] salt = new byte[64]; // limited by parse validation
        byte[] iv = new byte[32];   // limited by parse validation
        byte[] ciphertext = new byte[100];
        new java.security.SecureRandom().nextBytes(salt);
        new java.security.SecureRandom().nextBytes(iv);
        new java.security.SecureRandom().nextBytes(ciphertext);
        byte[] kdfId = {0x00, 0x01};

        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        ContainerParser.ContainerData parsed = ContainerParser.parse(container);
        assertArrayEquals(salt, parsed.salt, "Large salt should round-trip");
        assertArrayEquals(iv, parsed.iv, "Large IV should round-trip");
        assertArrayEquals(ciphertext, parsed.ciphertext, "Large ciphertext should round-trip");
    }

    // -------- CLI Edge Cases --------

    @Test
    public void testEncryptDecryptFullRoundtrip() throws Exception {
        // Simulate the full CLI roundtrip
        Path inputDir = tempDir.resolve("cli_test");
        Files.createDirectories(inputDir);
        Path inputFile = inputDir.resolve("test_roundtrip.txt");
        Files.writeString(inputFile, "Roundtrip test content");

        Path keyFile = tempDir.resolve("test_key.key");
        Path encryptedFile = tempDir.resolve("test.crbx");
        Path decryptedFile = tempDir.resolve("test_restored.txt");

        // Generate key
        byte[] key = CryptoEngine.generateKey();
        String encoded = Base64.getEncoder().encodeToString(key);
        Files.writeString(keyFile, encoded);

        // Encrypt using Cli
        // Note: We test the underlying functionality through FileProcessor
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, encryptedFile, key);
        processor.decryptFile(encryptedFile, decryptedFile, key);

        String decryptedContent = Files.readString(decryptedFile);
        assertEquals("Roundtrip test content", decryptedContent,
                "Full roundtrip should preserve content");
    }

    @Test
    public void testEncryptDecryptBinaryData() throws IOException {
        Path inputFile = tempDir.resolve("binary.bin");
        byte[] binaryData = new byte[256];
        new java.security.SecureRandom().nextBytes(binaryData);
        Files.write(inputFile, binaryData);

        Path encryptedFile = tempDir.resolve("binary.crbx");
        Path decryptedFile = tempDir.resolve("binary_restored.bin");

        byte[] key = CryptoEngine.generateKey();
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, encryptedFile, key);
        processor.decryptFile(encryptedFile, decryptedFile, key);

        byte[] restoredData = Files.readAllBytes(decryptedFile);
        assertArrayEquals(binaryData, restoredData, "Binary data should round-trip correctly");
    }
}