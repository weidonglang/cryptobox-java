package com.cryptobox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

/**
 * Tests for AES-256-GCM encryption and decryption engine.
 * <p>
 * Covers normal operation, edge cases (empty, 1 byte, 1MB),
 * authentication failure detection, and error handling.
 * </p>
 */
class CryptoEngineTest {

    private static final byte[] FIXED_KEY = new byte[Config.KEY_SIZE];
    private static final byte[] FIXED_IV = new byte[Config.IV_SIZE];

    static {
        // Fixed key for reproducible tests - NEVER use this in production!
        Arrays.fill(FIXED_KEY, (byte) 0x42);
        Arrays.fill(FIXED_IV, (byte) 0x24);
    }

    // ========== Basic Operation ==========

    @Test
    @DisplayName("encrypt and decrypt should return original data")
    void testEncryptDecryptRoundTrip() {
        byte[] plaintext = "Hello, Cryptobox!".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > plaintext.length); // Contains tag

        byte[] decrypted = CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("encrypt with fixed key and IV should produce deterministic ciphertext")
    void testDeterministicEncryption() {
        byte[] plaintext = "Test data".getBytes();

        byte[] ct1 = CryptoEngine.encrypt(plaintext, FIXED_KEY, FIXED_IV);
        byte[] ct2 = CryptoEngine.encrypt(plaintext, FIXED_KEY, FIXED_IV);

        assertArrayEquals(ct1, ct2);
    }

    // ========== IV Generation ==========

    @Test
    @DisplayName("generateIv should produce non-null IV of correct length")
    void testGenerateIv() {
        byte[] iv = CryptoEngine.generateIv();
        assertNotNull(iv);
        assertEquals(Config.IV_SIZE, iv.length);
    }

    @Test
    @DisplayName("generateIv should produce different IVs each time")
    void testGenerateIvUniqueness() {
        byte[] iv1 = CryptoEngine.generateIv();
        byte[] iv2 = CryptoEngine.generateIv();
        assertFalse(Arrays.equals(iv1, iv2));
    }

    // ========== Edge Cases ==========

    @Test
    @DisplayName("encrypt and decrypt empty byte array")
    void testEmptyData() {
        byte[] plaintext = new byte[0];
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length >= Config.GCM_TAG_SIZE);

        byte[] decrypted = CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("encrypt and decrypt single byte")
    void testSingleByte() {
        byte[] plaintext = new byte[]{(byte) 0xAB};
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] decrypted = CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("encrypt and decrypt large data (1MB)")
    void testLargeData() {
        byte[] plaintext = new byte[1024 * 1024]; // 1MB
        new java.util.Random(42).nextBytes(plaintext);
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] decrypted = CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("encrypt and decrypt data with various sizes")
    void testVariousSizes() {
        int[] sizes = {1, 16, 255, 256, 1000, 65535, 65536};
        for (int size : sizes) {
            byte[] plaintext = new byte[size];
            new java.util.Random(size).nextBytes(plaintext);
            byte[] iv = CryptoEngine.generateIv();

            byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
            byte[] decrypted = CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv);
            assertArrayEquals(plaintext, decrypted,
                    "Failed for size: " + size);
        }
    }

    // ========== Error Cases ==========

    @Test
    @DisplayName("decrypt with wrong key should throw DecryptionException")
    void testWrongKey() {
        byte[] plaintext = "Secret message".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        byte[] wrongKey = new byte[Config.KEY_SIZE];
        Arrays.fill(wrongKey, (byte) 0xFF);

        assertThrows(Errors.DecryptionException.class,
                () -> CryptoEngine.decrypt(ciphertext, wrongKey, iv));
    }

    @Test
    @DisplayName("decrypt with wrong IV should throw DecryptionException")
    void testWrongIv() {
        byte[] plaintext = "Secret message".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        byte[] wrongIv = new byte[Config.IV_SIZE];
        Arrays.fill(wrongIv, (byte) 0xFF);

        assertThrows(Errors.DecryptionException.class,
                () -> CryptoEngine.decrypt(ciphertext, FIXED_KEY, wrongIv));
    }

    @Test
    @DisplayName("decrypt corrupted ciphertext should throw DecryptionException")
    void testCorruptedCiphertext() {
        byte[] plaintext = "Important data".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        // Corrupt the first byte of ciphertext
        ciphertext[0] ^= 0xFF;

        assertThrows(Errors.DecryptionException.class,
                () -> CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv));
    }

    @Test
    @DisplayName("decrypt corrupted tag should throw DecryptionException")
    void testCorruptedTag() {
        byte[] plaintext = "Important data".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        // Corrupt the last byte (part of GCM tag)
        ciphertext[ciphertext.length - 1] ^= 0xFF;

        assertThrows(Errors.DecryptionException.class,
                () -> CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv));
    }

    @Test
    @DisplayName("decrypt empty ciphertext should throw exception")
    void testEmptyCiphertext() {
        byte[] empty = new byte[0];
        byte[] iv = CryptoEngine.generateIv();

        assertThrows(Errors.CryptoException.class,
                () -> CryptoEngine.decrypt(empty, FIXED_KEY, iv));
    }

    @Test
    @DisplayName("decrypt truncated ciphertext should throw exception")
    void testTruncatedCiphertext() {
        byte[] plaintext = "Some data to encrypt".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        // Truncate to just a few bytes
        byte[] truncated = Arrays.copyOf(ciphertext, 5);

        assertThrows(Errors.CryptoException.class,
                () -> CryptoEngine.decrypt(truncated, FIXED_KEY, iv));
    }

    @Test
    @DisplayName("encrypt with wrong key size should throw exception")
    void testEncryptWrongKeySize() {
        byte[] plaintext = "test".getBytes();
        byte[] iv = CryptoEngine.generateIv();
        byte[] shortKey = new byte[16]; // 128-bit, wrong size for AES-256

        assertThrows(Errors.CryptoException.class,
                () -> CryptoEngine.encrypt(plaintext, shortKey, iv));
    }

    // ========== Multiple Operations ==========

    @Test
    @DisplayName("multiple encrypt-decrypt operations should work")
    void testMultipleOperations() {
        for (int i = 0; i < 10; i++) {
            byte[] plaintext = ("Message " + i).getBytes();
            byte[] iv = CryptoEngine.generateIv();
            byte[] key = new byte[Config.KEY_SIZE];
            Arrays.fill(key, (byte) i);

            byte[] ciphertext = CryptoEngine.encrypt(plaintext, key, iv);
            byte[] decrypted = CryptoEngine.decrypt(ciphertext, key, iv);
            assertArrayEquals(plaintext, decrypted);
        }
    }

    // ========== Ciphertext Structure Validation ==========

    @Test
    @DisplayName("ciphertext should be plaintext length + GCM tag size")
    void testCiphertextLength() {
        byte[] plaintext = "Hello".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        assertEquals(plaintext.length + Config.GCM_TAG_SIZE, ciphertext.length);
    }

    @Test
    @DisplayName("ciphertext should not equal plaintext")
    void testCiphertextNotPlaintext() {
        byte[] plaintext = "Sensitive data".getBytes();
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        assertFalse(Arrays.equals(plaintext, ciphertext));
    }

    @Test
    @DisplayName("different IVs should produce different ciphertext")
    void testDifferentIvDifferentCiphertext() {
        byte[] plaintext = "Same plaintext".getBytes();

        byte[] iv1 = new byte[Config.IV_SIZE];
        Arrays.fill(iv1, (byte) 0x11);
        byte[] iv2 = new byte[Config.IV_SIZE];
        Arrays.fill(iv2, (byte) 0x22);

        byte[] ct1 = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv1);
        byte[] ct2 = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv2);

        assertFalse(Arrays.equals(ct1, ct2));
    }

    // ========== Unicode Support ==========

    @Test
    @DisplayName("encrypt and decrypt Unicode text")
    void testUnicodeText() {
        String unicodeText = "Hello 世界 こんにちは 안녕하세요! 123!@#$%";
        byte[] plaintext = unicodeText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] iv = CryptoEngine.generateIv();

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] decrypted = CryptoEngine.decrypt(ciphertext, FIXED_KEY, iv);

        String decryptedText = new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(unicodeText, decryptedText);
    }
}