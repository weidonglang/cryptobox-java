package com.cryptobox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for CLI command definitions and key generation/password workflows.
 */
public class CliHelpTest {

    @TempDir
    Path tempDir;

    /**
     * Tests that keygen generates a valid Base64-encoded 32-byte key file.
     */
    @Test
    public void testKeygenGeneratesValidKey() throws Exception {
        Path keyFile = tempDir.resolve("test.key");
        
        // Simulate keygen via direct API call
        byte[] key = CryptoEngine.generateKey();
        String encoded = Base64.getEncoder().encodeToString(key);
        Files.writeString(keyFile, encoded + System.lineSeparator());
        
        // Verify key file exists
        assertTrue(Files.exists(keyFile));
        
        // Verify loaded key
        byte[] loaded = Cli.loadKeyFromFile(keyFile.toString());
        assertArrayEquals(key, loaded);
        
        // Verify key is 32 bytes
        assertEquals(32, loaded.length);
    }

    /**
     * Tests that keygen handles Base64 decode properly.
     */
    @Test
    public void testKeygenBase64RoundTrip() throws Exception {
        Path keyFile = tempDir.resolve("roundtrip.key");
        
        byte[] originalKey = new byte[32];
        new SecureRandom().nextBytes(originalKey);
        
        String encoded = Base64.getEncoder().encodeToString(originalKey);
        Files.writeString(keyFile, encoded + System.lineSeparator());
        
        byte[] loaded = Cli.loadKeyFromFile(keyFile.toString());
        assertArrayEquals(originalKey, loaded);
    }

    /**
     * Tests that loading a non-existent key file throws FileOperationException.
     */
    @Test
    public void testLoadKeyFromNonExistentFile() {
        String fakePath = tempDir.resolve("nonexistent.key").toString();
        assertThrows(Errors.FileOperationException.class, () -> {
            Cli.loadKeyFromFile(fakePath);
        });
    }

    /**
     * Tests that clearKey properly zeroes the byte array.
     */
    @Test
    public void testClearKey() {
        byte[] key = new byte[]{1, 2, 3, 4, 5};
        Cli.clearKey(key);
        for (byte b : key) {
            assertEquals(0, b);
        }
    }

    /**
     * Tests that clearKey handles null safely.
     */
    @Test
    public void testClearKeyNull() {
        // Should not throw
        Cli.clearKey(null);
    }

    /**
     * Tests password derivation verification: same password + same salt = same key.
     * Uses separate copies of password since deriveKeyFromPassword clears the char array.
     */
    @Test
    public void testPasswordDerivationConsistency() {
        byte[] salt = KeyDerivation.generateSalt();
        
        char[] password1 = "TestPassword123!".toCharArray();
        char[] password2 = "TestPassword123!".toCharArray();
        
        byte[] key1 = KeyDerivation.deriveKeyFromPassword(password1, salt);
        byte[] key2 = KeyDerivation.deriveKeyFromPassword(password2, salt);
        
        assertArrayEquals(key1, key2);
        assertEquals(32, key1.length);
    }

    /**
     * Tests that different passwords produce different keys.
     */
    @Test
    public void testDifferentPasswordsDifferentKeys() {
        byte[] salt = KeyDerivation.generateSalt();
        
        char[] pw1 = "password1".toCharArray();
        char[] pw2 = "password2".toCharArray();
        
        byte[] key1 = KeyDerivation.deriveKeyFromPassword(pw1, salt);
        byte[] key2 = KeyDerivation.deriveKeyFromPassword(pw2, salt);
        
        assertFalse(java.util.Arrays.equals(key1, key2));
    }

    /**
     * Tests that verify tag works with a correctly encrypted container.
     */
    @Test
    public void testVerifyContainerWithTag() throws Exception {
        // Create a test container
        byte[] key = CryptoEngine.generateKey();
        byte[] plaintext = "Test data for verification".getBytes();
        byte[] salt = KeyDerivation.generateSalt();
        byte[] iv = CryptoEngine.generateIv();
        
        byte[] ciphertext = CryptoEngine.encrypt(plaintext, key, iv);
        byte[] kdfId = {0x00, Config.KDF_PBKDF2};
        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        
        // Verify tag should succeed
        assertTrue(ContainerParser.verifyTag(container, key));
    }

    /**
     * Tests that verify tag fails with wrong key.
     */
    @Test
    public void testVerifyContainerWithWrongKey() throws Exception {
        byte[] key = CryptoEngine.generateKey();
        byte[] wrongKey = CryptoEngine.generateKey();
        byte[] plaintext = "Test data".getBytes();
        byte[] salt = KeyDerivation.generateSalt();
        byte[] iv = CryptoEngine.generateIv();
        
        byte[] ciphertext = CryptoEngine.encrypt(plaintext, key, iv);
        byte[] kdfId = {0x00, Config.KDF_PBKDF2};
        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        
        // Verify tag with wrong key should throw
        assertThrows(Errors.DecryptionException.class, () -> {
            ContainerParser.verifyTag(container, wrongKey);
        });
    }

    /**
     * Tests that loadKeyFromFile handles key correctly.
     */
    @Test
    public void testLoadKeyFromFileInvalidContent() throws Exception {
        Path keyFile = tempDir.resolve("invalid.key");
        Files.writeString(keyFile, "not-base64-content");
        
        assertThrows(Exception.class, () -> {
            Cli.loadKeyFromFile(keyFile.toString());
        });
    }

    /**
     * Tests encrypt and decrypt round-trip with password-derived key.
     * Derives the key from password + salt, then uses FileProcessor
     * (which uses the key directly since deriveFileKey is a no-op).
     */
    @Test
    public void testEncryptDecryptWithPasswordDerivedKey() throws Exception {
        char[] password = "MySecretPassword123!".toCharArray();
        byte[] salt = KeyDerivation.generateSalt();
        
        // Derive key from password
        byte[] derivedKey = KeyDerivation.deriveKeyFromPassword(password, salt);
        
        try {
            // Encrypt
            Path inputFile = tempDir.resolve("secret.txt");
            Path outputFile = tempDir.resolve("secret.crbx");
            Path restoredFile = tempDir.resolve("secret_restored.txt");
            
            Files.writeString(inputFile, "This is secret text that should be encrypted.");
            
            FileProcessor processor = new FileProcessor();
            processor.encryptFile(inputFile, outputFile, derivedKey);
            
            // Decrypt with same key
            processor.decryptFile(outputFile, restoredFile, derivedKey);
            
            // Verify content matches
            String restored = Files.readString(restoredFile);
            assertEquals("This is secret text that should be encrypted.", restored);
        } finally {
            java.util.Arrays.fill(derivedKey, (byte) 0);
        }
    }

    /**
     * Tests that decrypt with wrong password-derived key fails.
     * The password-based decrypt test uses CryptoEngine directly (bypassing
     * FileProcessor's deriveFileKey no-op) to properly test password KDF failure.
     */
    @Test
    public void testDecryptWithWrongPasswordDerivedKey() throws Exception {
        char[] password = "CorrectPassword".toCharArray();
        byte[] salt = KeyDerivation.generateSalt();
        byte[] correctKey = KeyDerivation.deriveKeyFromPassword(password, salt);
        
        try {
            // Build a container manually with password-derived key
            Path inputFile = tempDir.resolve("secret.txt");
            Path outputFile = tempDir.resolve("secret.crbx");
            Path restoredFile = tempDir.resolve("secret_restored.txt");
            
            Files.writeString(inputFile, "Sensitive data");
            
            byte[] plaintext = Files.readAllBytes(inputFile);
            byte[] iv = CryptoEngine.generateIv();
            byte[] ciphertext = CryptoEngine.encrypt(plaintext, correctKey, iv);
            byte[] kdfId = {0x00, Config.KDF_PBKDF2};
            byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
            Files.write(outputFile, container);
            
            // Try to decrypt with wrong password
            byte[] wrongKey = KeyDerivation.deriveKeyFromPassword("WrongPassword".toCharArray(), salt);
            
            try {
                byte[] containerData = Files.readAllBytes(outputFile);
                ContainerParser.ContainerData parsed = ContainerParser.parse(containerData);
                assertThrows(Errors.DecryptionException.class, () -> {
                    CryptoEngine.decrypt(parsed.ciphertext, wrongKey, parsed.iv);
                });
            } finally {
                java.util.Arrays.fill(wrongKey, (byte) 0);
            }
        } finally {
            java.util.Arrays.fill(correctKey, (byte) 0);
        }
    }

    /**
     * Tests that password char arrays are zeroed after derivation.
     */
    @Test
    public void testPasswordClearedAfterDerivation() {
        byte[] salt = KeyDerivation.generateSalt();
        char[] password = "SensitivePassword!".toCharArray();
        
        // Derive (the method should clear password)
        byte[] key = KeyDerivation.deriveKeyFromPassword(password, salt);
        
        assertNotNull(key);
        assertEquals(32, key.length);
        
        // Password should be cleared now
        for (char c : password) {
            assertEquals('\0', c);
        }
    }
}