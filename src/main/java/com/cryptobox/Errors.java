package com.cryptobox;

/**
 * Custom exception hierarchy for Cryptobox operations.
 * Provides clear separation between different error types
 * without exposing sensitive information in error messages.
 */
public class Errors {

    private Errors() {
        // Utility class - prevent instantiation
    }

    /** Base exception for all Cryptobox errors. */
    public static class CryptoboxException extends RuntimeException {
        public CryptoboxException(String message) {
            super(message);
        }
        public CryptoboxException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when container format validation fails. */
    public static class ContainerFormatException extends CryptoboxException {
        public ContainerFormatException(String message) {
            super(message);
        }
        public ContainerFormatException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when decryption fails (wrong key or corrupted data). */
    public static class DecryptionException extends CryptoboxException {
        public DecryptionException(String message) {
            super(message);
        }
        public DecryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when a cryptographic operation fails. */
    public static class CryptoException extends CryptoboxException {
        public CryptoException(String message) {
            super(message);
        }
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when a file operation fails. */
    public static class FileOperationException extends CryptoboxException {
        public FileOperationException(String message) {
            super(message);
        }
        public FileOperationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when key derivation fails. */
    public static class KeyDerivationException extends CryptoboxException {
        public KeyDerivationException(String message) {
            super(message);
        }
        public KeyDerivationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when integrity verification fails. */
    public static class IntegrityException extends CryptoboxException {
        public IntegrityException(String message) {
            super(message);
        }
        public IntegrityException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}