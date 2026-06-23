package com.cryptobox;

/**
 * Configuration constants for Cryptobox operations.
 * <p>
 * Defines algorithm parameters, container format constants,
 * and default values used across all modules.
 * </p>
 */
public final class Config {

    private Config() {
        // Utility class - prevent instantiation
    }

    // --- Container Format ---
    /** Magic bytes for Cryptobox container: "CRBX" */
    public static final byte[] MAGIC = {0x43, 0x52, 0x42, 0x58}; // "CRBX"

    /** Container version (v1 = 0x0001) */
    public static final byte[] VERSION_BYTES = {0x00, 0x01};

    /** Algorithm ID for AES-256-GCM */
    public static final byte ALGORITHM_AES256_GCM = 0x01;

    /** KDF ID for Argon2id */
    public static final byte KDF_ARGON2ID = 0x01;

    /** KDF ID for PBKDF2 */
    public static final byte KDF_PBKDF2 = 0x02;

    // --- AES-256-GCM ---
    /** AES-256 key size in bytes */
    public static final int KEY_SIZE = 32;

    /** GCM IV size in bytes */
    public static final int IV_SIZE = 12;

    /** GCM authentication tag size in bytes (128 bits) */
    public static final int GCM_TAG_SIZE = 16;

    // --- Key Derivation ---
    /** Salt size in bytes */
    public static final int SALT_SIZE = 16;

    /** Argon2id memory cost in KB (64MB) */
    public static final int ARGON2_MEMORY = 65536; // 64 * 1024

    /** Argon2id iteration count */
    public static final int ARGON2_ITERATIONS = 3;

    /** Argon2id parallelism */
    public static final int ARGON2_PARALLELISM = 4;

    /** PBKDF2 iteration count */
    public static final int PBKDF2_ITERATIONS = 600000;

    /** PBKDF2 algorithm */
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";

    // --- Container Field Sizes ---
    public static final int MAGIC_LENGTH = 4;
    public static final int VERSION_LENGTH = 2;
    public static final int ALGORITHM_ID_LENGTH = 2;
    public static final int KDF_ID_LENGTH = 2;
    public static final int SALT_LENGTH_FIELD_SIZE = 2;
    public static final int IV_LENGTH_FIELD_SIZE = 2;
    public static final int CIPHERTEXT_LENGTH_FIELD_SIZE = 4;
}