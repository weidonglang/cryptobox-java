package com.cryptobox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

/**
 * Tests for key derivation functions.
 * <p>
 * Covers Argon2id, PBKDF2, key generation, Base64 encoding/decoding,
 * salt generation, and memory clearing operations.
 * </p>
 */
class KeyDerivationTest {

    // ========== Salt Generation ==========

    @Test
    @DisplayName("generateSalt should produce non-null salt of correct length")
    void testGenerateSalt() {
        byte[] salt = KeyDerivation.generateSalt();
        assertNotNull(salt);
        assertEquals(Config.SALT_SIZE, salt.length);
    }

    @Test
    @DisplayName("generateSalt should produce different salts each time")
    void testGenerateSaltUniqueness() {
        byte[] salt1 = KeyDerivation.generateSalt();
        byte[] salt2 = KeyDerivation.generateSalt();
        assertFalse(Arrays.equals(salt1, salt2));
    }

    // ========== Key Generation ==========

    @Test
    @DisplayName("generateKey should produce non-null key of correct length")
    void testGenerateKey() {
        byte[] key = KeyDerivation.generateKey();
        assertNotNull(key);
        assertEquals(Config.KEY_SIZE, key.length);
    }

    @Test
    @DisplayName("generateKey should produce different keys each time")
    void testGenerateKeyUniqueness() {
        byte[] key1 = KeyDerivation.generateKey();
        byte[] key2 = KeyDerivation.generateKey();
        assertFalse(Arrays.equals(key1, key2));
    }

    // ========== PBKDF2 Derivation ==========

    @Test
    @DisplayName("PBKDF2 should derive consistent key from same password and salt")
    void testPbkdf2Consistency() {
        char[] password = "TestPassword123!".toCharArray();
        byte[] salt = "0123456789abcdef".getBytes(); // Fixed salt for reproducibility

        byte[] key1 = KeyDerivation.deriveKeyWithPbkdf2(password, salt);
        // Password array should be zeroed now, create fresh copy
        char[] password2 = "TestPassword123!".toCharArray();
        byte[] key2 = KeyDerivation.deriveKeyWithPbkdf2(password2, salt);

        assertArrayEquals(key1, key2);
    }

    @Test
    @DisplayName("PBKDF2 should produce 32-byte key")
    void testPbkdf2KeyLength() {
        char[] password = "password".toCharArray();
        byte[] salt = KeyDerivation.generateSalt();

        byte[] key = KeyDerivation.deriveKeyWithPbkdf2(password, salt);
        assertEquals(Config.KEY_SIZE, key.length);
    }

    @Test
    @DisplayName("PBKDF2 should produce different keys for different passwords")
    void testPbkdf2DifferentPasswords() {
        byte[] salt = "0123456789abcdef".getBytes();

        char[] pwd1 = "password1".toCharArray();
        byte[] key1 = KeyDerivation.deriveKeyWithPbkdf2(pwd1, salt);

        char[] pwd2 = "password2".toCharArray();
        byte[] key2 = KeyDerivation.deriveKeyWithPbkdf2(pwd2, salt);

        assertFalse(Arrays.equals(key1, key2));
    }

    @Test
    @DisplayName("PBKDF2 should produce different keys for different salts")
    void testPbkdf2DifferentSalts() {
        char[] password = "password".toCharArray();

        byte[] salt1 = "0123456789abcdef".getBytes();
        byte[] key1 = KeyDerivation.deriveKeyWithPbkdf2(password, salt1);

        char[] password2 = "password".toCharArray();
        byte[] salt2 = "fedcba9876543210".getBytes();
        byte[] key2 = KeyDerivation.deriveKeyWithPbkdf2(password2, salt2);

        assertFalse(Arrays.equals(key1, key2));
    }

    @Test
    @DisplayName("PBKDF2 should handle empty password")
    void testPbkdf2EmptyPassword() {
        char[] password = "".toCharArray();
        byte[] salt = KeyDerivation.generateSalt();

        byte[] key = KeyDerivation.deriveKeyWithPbkdf2(password, salt);
        assertEquals(Config.KEY_SIZE, key.length);
    }

    @Test
    @DisplayName("PBKDF2 should handle Unicode password")
    void testPbkdf2UnicodePassword() {
        char[] password = "密码123!@#$%^&*()".toCharArray();
        byte[] salt = "0123456789abcdef".getBytes();

        byte[] key = KeyDerivation.deriveKeyWithPbkdf2(password, salt);
        assertEquals(Config.KEY_SIZE, key.length);

        char[] password2 = "密码123!@#$%^&*()".toCharArray();
        byte[] key2 = KeyDerivation.deriveKeyWithPbkdf2(password2, salt);
        assertArrayEquals(key, key2);
    }

    // ========== Argon2id Derivation ==========

    @Test
    @DisplayName("Argon2id should produce 32-byte key")
    void testArgon2idKeyLength() {
        char[] password = "password".toCharArray();
        byte[] salt = KeyDerivation.generateSalt();

        byte[] key = KeyDerivation.deriveKeyWithArgon2id(password, salt);
        assertEquals(Config.KEY_SIZE, key.length);
    }

    @Test
    @DisplayName("Argon2id should produce consistent key from same password and salt")
    void testArgon2idConsistency() {
        byte[] salt = "0123456789abcdef".getBytes();

        char[] pwd1 = "testPassword".toCharArray();
        byte[] key1 = KeyDerivation.deriveKeyWithArgon2id(pwd1, salt);

        char[] pwd2 = "testPassword".toCharArray();
        byte[] key2 = KeyDerivation.deriveKeyWithArgon2id(pwd2, salt);

        assertArrayEquals(key1, key2);
    }

    @Test
    @DisplayName("Argon2id should produce different keys for different passwords")
    void testArgon2idDifferentPasswords() {
        byte[] salt = "0123456789abcdef".getBytes();

        char[] pwd1 = "password1".toCharArray();
        byte[] key1 = KeyDerivation.deriveKeyWithArgon2id(pwd1, salt);

        char[] pwd2 = "password2".toCharArray();
        byte[] key2 = KeyDerivation.deriveKeyWithArgon2id(pwd2, salt);

        assertFalse(Arrays.equals(key1, key2));
    }

    // ========== Derive from Password (dispatch) ==========

    @Test
    @DisplayName("deriveKeyFromPassword with PBKDF2 should work")
    void testDeriveKeyFromPasswordPbkdf2() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = "0123456789abcdef".getBytes();

        byte[] key = KeyDerivation.deriveKeyFromPassword(password, salt, Config.KDF_PBKDF2);
        assertEquals(Config.KEY_SIZE, key.length);
    }

    @Test
    @DisplayName("deriveKeyFromPassword with Argon2id should work")
    void testDeriveKeyFromPasswordArgon2id() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = "0123456789abcdef".getBytes();

        byte[] key = KeyDerivation.deriveKeyFromPassword(password, salt, Config.KDF_ARGON2ID);
        assertEquals(Config.KEY_SIZE, key.length);
    }

    @Test
    @DisplayName("deriveKeyFromPassword should throw on unsupported KDF")
    void testDeriveKeyFromPasswordInvalidKdf() {
        char[] password = "test".toCharArray();
        byte[] salt = "0123456789abcdef".getBytes();

        assertThrows(Errors.KeyDerivationException.class,
                () -> KeyDerivation.deriveKeyFromPassword(password, salt, (byte) 0xFF));
    }

    @Test
    @DisplayName("deriveKeyFromPassword default should use PBKDF2")
    void testDeriveKeyFromPasswordDefault() {
        char[] password = "test".toCharArray();
        byte[] salt = "0123456789abcdef".getBytes();

        byte[] key = KeyDerivation.deriveKeyFromPassword(password, salt);
        assertEquals(Config.KEY_SIZE, key.length);
    }

    // ========== Password Clearing ==========

    @Test
    @DisplayName("deriveKeyFromPassword should zero the password array")
    void testPasswordCleared() {
        char[] password = "sensitivePassword!123".toCharArray();
        byte[] salt = "0123456789abcdef".getBytes();

        // Store original chars for comparison
        char[] original = Arrays.copyOf(password, password.length);

        KeyDerivation.deriveKeyFromPassword(password, salt);

        // Password should be zeroed
        for (char c : password) {
            assertEquals('\0', c);
        }
    }

    @Test
    @DisplayName("clearPassword should zero out char array")
    void testClearPassword() {
        char[] password = "test123".toCharArray();
        KeyDerivation.clearPassword(password);

        for (char c : password) {
            assertEquals('\0', c);
        }
    }

    @Test
    @DisplayName("clearPassword should handle null")
    void testClearPasswordNull() {
        // Should not throw
        KeyDerivation.clearPassword(null);
    }

    @Test
    @DisplayName("clearKey should zero out byte array")
    void testClearKey() {
        byte[] key = {0x01, 0x02, 0x03, 0x04};
        KeyDerivation.clearKey(key);

        for (byte b : key) {
            assertEquals(0, b);
        }
    }

    @Test
    @DisplayName("clearKey should handle null")
    void testClearKeyNull() {
        // Should not throw
        KeyDerivation.clearKey(null);
    }

    // ========== Base64 Encoding/Decoding ==========

    @Test
    @DisplayName("encodeKeyToBase64 should produce valid Base64 string")
    void testEncodeKeyToBase64() {
        byte[] key = new byte[Config.KEY_SIZE];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }

        String encoded = KeyDerivation.encodeKeyToBase64(key);
        assertNotNull(encoded);
        assertFalse(encoded.isEmpty());
    }

    @Test
    @DisplayName("encode and decode should be inverse operations")
    void testEncodeDecodeRoundTrip() {
        byte[] original = KeyDerivation.generateKey();
        String encoded = KeyDerivation.encodeKeyToBase64(original);
        byte[] decoded = KeyDerivation.decodeKeyFromBase64(encoded);

        assertArrayEquals(original, decoded);
    }

    @Test
    @DisplayName("decodeKeyFromBase64 should reject wrong-length keys")
    void testDecodeKeyInvalidLength() {
        // 16 bytes is wrong (should be 32)
        byte[] shortKey = new byte[16];
        Arrays.fill(shortKey, (byte) 0x42);
        String encoded = KeyDerivation.encodeKeyToBase64(shortKey);

        assertThrows(Errors.KeyDerivationException.class,
                () -> KeyDerivation.decodeKeyFromBase64(encoded));
    }

    @Test
    @DisplayName("decodeKeyFromBase64 should reject invalid Base64")
    void testDecodeKeyInvalidBase64() {
        assertThrows(Errors.KeyDerivationException.class,
                () -> KeyDerivation.decodeKeyFromBase64("not-valid-base64!!!"));
    }

    @Test
    @DisplayName("decodeKeyFromBase64 should handle whitespace in input")
    void testDecodeKeyWithWhitespace() {
        byte[] key = KeyDerivation.generateKey();
        String encoded = "  " + KeyDerivation.encodeKeyToBase64(key) + "\n  ";
        byte[] decoded = KeyDerivation.decodeKeyFromBase64(encoded);

        assertArrayEquals(key, decoded);
    }
}