package com.cryptobox;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM encryption and decryption engine.
 * <p>
 * Provides low-level cryptographic operations using JDK built-in AES-GCM.
 * All keys and sensitive data are cleared from memory after use.
 * </p>
 */
public final class CryptoEngine {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoEngine() {
        // Utility class - prevent instantiation
    }

    /**
     * Generates a random 256-bit AES key.
     *
     * @return a 32-byte random key
     */
    public static byte[] generateKey() {
        byte[] key = new byte[Config.KEY_SIZE];
        RANDOM.nextBytes(key);
        return key;
    }

    /**
     * Encrypts plaintext using AES-256-GCM.
     *
     * @param plaintext the data to encrypt
     * @param key       32-byte AES key
     * @param iv        12-byte initialization vector
     * @return ciphertext including 16-byte GCM tag appended at the end
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv) {
        try {
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(Config.GCM_TAG_SIZE * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new Errors.CryptoException("Encryption failed", e);
        }
    }

    /**
     * Decrypts ciphertext using AES-256-GCM.
     *
     * @param ciphertext data to decrypt (includes 16-byte GCM tag)
     * @param key        32-byte AES key
     * @param iv         12-byte initialization vector
     * @return decrypted plaintext
     * @throws Errors.DecryptionException if authentication fails
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) {
        try {
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(Config.GCM_TAG_SIZE * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher.doFinal(ciphertext);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new Errors.DecryptionException("Decryption failed: wrong key or corrupted data", e);
        } catch (Exception e) {
            throw new Errors.CryptoException("Decryption failed", e);
        }
    }

    /**
     * Generates a random IV for GCM mode.
     *
     * @return 12 random bytes
     */
    public static byte[] generateIv() {
        byte[] iv = new byte[Config.IV_SIZE];
        RANDOM.nextBytes(iv);
        return iv;
    }
}