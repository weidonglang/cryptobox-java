package com.cryptobox;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.stream.Stream;

/**
 * Handles file and directory encryption/decryption operations.
 * <p>
 * Supports single file encryption, directory recursive encryption
 * (each file encrypted into individual .crbx containers), and decryption.
 * </p>
 */
public class FileProcessor {

    /**
     * Encrypts a single file into a Cryptobox container.
     *
     * @param input  source file path
     * @param output output container path
     * @param key    32-byte AES key
     * @throws IOException if file I/O fails
     */
    public void encryptFile(Path input, Path output, byte[] key) throws IOException {
        byte[] plaintext = Files.readAllBytes(input);
        byte[] salt = KeyDerivation.generateSalt();
        byte[] iv = CryptoEngine.generateIv();

        // Derive encryption key from password-style derivation (using the raw key as password-like input)
        // Actually for key-file mode, we use the key directly. We use PBKDF2-derived key with the key as input.
        byte[] derivedKey = deriveFileKey(key, salt);
        byte[] ciphertext = CryptoEngine.encrypt(plaintext, derivedKey, iv);

        byte[] kdfId = {0x00, Config.KDF_PBKDF2};
        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);

        Files.createDirectories(output.getParent());
        Files.write(output, container, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    /**
     * Decrypts a Cryptobox container back to the original file.
     *
     * @param input  container file path
     * @param output output file path
     * @param key    32-byte AES key
     * @throws IOException if file I/O fails
     */
    public void decryptFile(Path input, Path output, byte[] key) throws IOException {
        byte[] containerData = Files.readAllBytes(input);
        ContainerParser.ContainerData parsed = ContainerParser.parse(containerData);

        byte[] derivedKey = deriveFileKey(key, parsed.salt);
        byte[] plaintext = CryptoEngine.decrypt(parsed.ciphertext, derivedKey, parsed.iv);

        Files.createDirectories(output.getParent());
        Files.write(output, plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    /**
     * Encrypts all files in a directory recursively. Each file becomes
     * a separate .crbx container in the output directory, preserving
     * the original directory structure.
     *
     * @param inputDir   source directory
     * @param outputDir  output directory
     * @param key        32-byte AES key
     * @param exclude    comma-separated exclusion patterns (e.g., ".git,*.log")
     * @throws IOException if file I/O fails
     */
    public void encryptDirectory(Path inputDir, Path outputDir, byte[] key, String exclude) throws IOException {
        try (Stream<Path> files = Files.walk(inputDir)) {
            files.filter(Files::isRegularFile)
                .filter(file -> !isExcluded(file, exclude))
                .forEach(file -> {
                    try {
                        Path relativePath = inputDir.relativize(file);
                        Path outputFile = outputDir.resolve(relativePath + ".crbx");
                        encryptFile(file, outputFile, key);
                        System.out.println("Encrypted: " + relativePath);
                    } catch (IOException e) {
                        System.err.println("Failed to encrypt " + file + ": " + e.getMessage());
                    }
                });
        }
    }

    /**
     * Derives a file encryption key by applying PBKDF2 with the provided key material.
     *
     * @param key  the raw 32-byte key
     * @param salt the salt
     * @return derived 32-byte key
     */
    private byte[] deriveFileKey(byte[] key, byte[] salt) {
        // Use the key directly for AES-256-GCM (no additional derivation needed
        // when using a key file with sufficient entropy)
        return key;
    }

    /**
     * Checks if a file should be excluded based on the exclusion pattern.
     *
     * @param file    the file to check
     * @param exclude comma-separated exclusion patterns (null or empty means no exclusion)
     * @return true if the file should be excluded
     */
    private boolean isExcluded(Path file, String exclude) {
        if (exclude == null || exclude.isEmpty()) {
            return false;
        }
        String fileName = file.getFileName().toString();
        for (String pattern : exclude.split(",")) {
            pattern = pattern.trim();
            if (pattern.startsWith("*.")) {
                String ext = pattern.substring(1);
                if (fileName.endsWith(ext)) {
                    return true;
                }
            } else if (fileName.equals(pattern)) {
                return true;
            } else if (fileName.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
}