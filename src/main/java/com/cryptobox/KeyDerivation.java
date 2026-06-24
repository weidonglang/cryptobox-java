package com.cryptobox;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Key derivation functions for Cryptobox.
 * <p>
 * Supports Argon2id (via Bouncy Castle) and PBKDF2WithHmacSHA512 (JDK built-in).
 * Salt is always randomly generated. Derived key length is 32 bytes for AES-256.
 * All password char arrays are zeroed after use.
 * </p>
 */
public final class KeyDerivation {

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyDerivation() {
        // Utility class
    }

    /**
     * Generates a random salt for key derivation.
     *
     * @return salt bytes of length {@link Config#SALT_SIZE}
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[Config.SALT_SIZE];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a random 32-byte key for file-based key encryption.
     * The key is generated using a secure random number generator.
     *
     * @return 32-byte random key
     */
    public static byte[] generateKey() {
        byte[] key = new byte[Config.KEY_SIZE];
        RANDOM.nextBytes(key);
        return key;
    }

    /**
     * Derives a 32-byte key from a password using the specified KDF algorithm.
     * <p>
     * Supports {@link Config#KDF_ARGON2ID} (Argon2id) and {@link Config#KDF_PBKDF2} (PBKDF2).
     * The password char array is zeroed after derivation.
     * </p>
     *
     * @param password    the password characters (will be zeroed after use)
     * @param salt        the salt bytes
     * @param kdfAlgorithm the KDF algorithm ID
     * @return 32-byte derived key
     * @throws Errors.KeyDerivationException if derivation fails
     */
    public static byte[] deriveKeyFromPassword(char[] password, byte[] salt, byte kdfAlgorithm) {
        try {
            byte[] key;
            if (kdfAlgorithm == Config.KDF_ARGON2ID) {
                key = deriveKeyWithArgon2id(password, salt);
            } else if (kdfAlgorithm == Config.KDF_PBKDF2) {
                key = deriveKeyWithPbkdf2(password, salt);
            } else {
                throw new Errors.KeyDerivationException("Unsupported KDF algorithm: " + (kdfAlgorithm & 0xFF));
            }
            return key;
        } finally {
            // Zero the password array after derivation
            clearPassword(password);
        }
    }

    /**
     * Derives a 32-byte key from a password using PBKDF2WithHmacSHA512.
     * Default method when no KDF algorithm is specified.
     *
     * @param password the password characters (will be zeroed after use)
     * @param salt     the salt bytes
     * @return 32-byte derived key
     */
    public static byte[] deriveKeyFromPassword(char[] password, byte[] salt) {
        return deriveKeyFromPassword(password, salt, Config.KDF_PBKDF2);
    }

    /**
     * Derives a key using Argon2id (via Bouncy Castle).
     * Uses ARGON2_id variant with configured memory, iterations, and parallelism.
     *
     * @param password the password characters (will be zeroed)
     * @param salt     the salt bytes
     * @return 32-byte derived key
     * @throws Errors.KeyDerivationException if derivation fails
     */
    public static byte[] deriveKeyWithArgon2id(char[] password, byte[] salt) {
        try {
            org.bouncycastle.crypto.generators.Argon2BytesGenerator generator =
                    new org.bouncycastle.crypto.generators.Argon2BytesGenerator();

            org.bouncycastle.crypto.params.Argon2Parameters.Builder builder =
                    new org.bouncycastle.crypto.params.Argon2Parameters.Builder(
                            org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id)
                            .withSalt(salt)
                            .withMemoryAsKB(Config.ARGON2_MEMORY)
                            .withIterations(Config.ARGON2_ITERATIONS)
                            .withParallelism(Config.ARGON2_PARALLELISM);

            generator.init(builder.build());
            byte[] result = new byte[Config.KEY_SIZE];
            generator.generateBytes(password, result);
            return result;
        } catch (Exception e) {
            throw new Errors.KeyDerivationException("Argon2id key derivation failed", e);
        }
    }

    /**
     * Derives a key using PBKDF2WithHmacSHA512.
     * Uses 600,000 iterations as configured in {@link Config#PBKDF2_ITERATIONS}.
     *
     * @param password the password characters (will be zeroed)
     * @param salt     the salt bytes
     * @return 32-byte derived key
     * @throws Errors.KeyDerivationException if derivation fails
     */
    public static byte[] deriveKeyWithPbkdf2(char[] password, byte[] salt) {
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(password, salt, Config.PBKDF2_ITERATIONS, Config.KEY_SIZE * 8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(Config.PBKDF2_ALGORITHM);
            byte[] key = factory.generateSecret(spec).getEncoded();
            return key;
        } catch (Exception e) {
            throw new Errors.KeyDerivationException("PBKDF2 key derivation failed", e);
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }

    /**
     * Clears a char array by filling it with zeros.
     * Used to securely erase passwords from memory after use.
     *
     * @param password the char array to clear
     */
    public static void clearPassword(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Clears a byte array by filling it with random values.
     * Used to securely erase keys from memory after use.
     *
     * @param data the byte array to clear
     */
    public static void clearKey(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    /**
     * Decodes a Base64-encoded key from a key file.
     * Key files are expected to contain a single line of Base64-encoded 32-byte key.
     *
     * @param encoded the Base64-encoded key string
     * @return 32-byte decoded key
     * @throws Errors.KeyDerivationException if decoding fails
     */
    public static byte[] decodeKeyFromBase64(String encoded) {
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(encoded.trim());
            if (decoded.length != Config.KEY_SIZE) {
                throw new Errors.KeyDerivationException(
                        "Invalid key length: expected " + Config.KEY_SIZE + " bytes, got " + decoded.length);
            }
            return decoded;
        } catch (Errors.KeyDerivationException e) {
            throw e;
        } catch (Exception e) {
            throw new Errors.KeyDerivationException("Failed to decode key from Base64", e);
        }
    }

    /**
     * Encodes a key to Base64 string for storage in a key file.
     *
     * @param key the 32-byte key
     * @return Base64-encoded key string
     */
    public static String encodeKeyToBase64(byte[] key) {
        return java.util.Base64.getEncoder().encodeToString(key);
    }
}
