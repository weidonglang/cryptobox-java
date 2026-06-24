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
    public void testInvalidKeySize() {
        byte[] invalidKey = new byte[16]; // 128-bit, not 256-bit
        byte[] iv = CryptoEngine.generateIv();
        assertThrows(Errors.CryptoException.class, () ->
                        CryptoEngine.encrypt("data".getBytes(), invalidKey, iv),
                "Encryption with wrong key size should throw CryptoException");
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
}