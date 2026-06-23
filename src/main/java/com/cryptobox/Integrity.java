package com.cryptobox;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA256 integrity verification utility.
 * <p>
 * Computes and verifies SHA-256 hashes of files.
 * Used for integrity checks before/after encryption operations.
 * </p>
 */
public final class Integrity {

    private Integrity() {
        // Utility class
    }

    /**
     * Computes the SHA-256 hash of a file.
     *
     * @param path path to the file
     * @return hexadecimal SHA-256 hash string
     * @throws IOException if file cannot be read
     */
    public static String computeHash(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int bytesRead;

            try (InputStream is = Files.newInputStream(path)) {
                while ((bytesRead = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            throw new Errors.CryptoException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Computes the SHA-256 hash of a byte array.
     *
     * @param data the data to hash
     * @return hexadecimal SHA-256 hash string
     */
    public static String computeHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data);
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            throw new Errors.CryptoException("SHA-256 algorithm not available", e);
        }
    }
}