package com.cryptobox;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

/**
 * Key derivation functions for Cryptobox.
 * <p>
 * Supports Argon2id (via Bouncy Castle) and PBKDF2WithHmacSHA512 (JDK built-in).
 * Salt is always randomly generated. Derived key length is 32 bytes for AES-256.
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
     * Derives a 32-byte key from a password using PBKDF2WithHmacSHA512.
     * <p>
     * Uses 600,000 iterations and 16-byte random salt.
     * The password char array is zeroed after derivation.
     * </p>
     *
     * @param password the password characters (will be zeroed)
     * @param salt     the salt bytes
     * @return 32-byte derived key
     */
    public static byte[] deriveKeyFromPassword(char[] password, byte[] salt) {
        return deriveKeyWithPbkdf2(password, salt);
    }

    /**
     * Derives a key using PBKDF2WithHmacSHA512.
     *
     * @param password the password
     * @param salt     the salt
     * @return 32-byte derived key
     */
    private static byte[] deriveKeyWithPbkdf2(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, Config.PBKDF2_ITERATIONS, Config.KEY_SIZE * 8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(Config.PBKDF2_ALGORITHM);
            byte[] key = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (Exception e) {
            throw new Errors.KeyDerivationException("PBKDF2 key derivation failed", e);
        }
    }

    /**
     * Derives a key using Argon2id (via Bouncy Castle).
     *
     * @param password the password characters (will be zeroed)
     * @param salt     the salt bytes
     * @return 32-byte derived key
     */
    public static byte[] deriveKeyWithArgon2id(char[] password, byte[] salt) {
        try {
            // Use Bouncy Castle's Argon2 implementation
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
}