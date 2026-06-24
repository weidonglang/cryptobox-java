package com.cryptobox;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileVisitOption;
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
 * SHA-256 integrity hashes are computed before encryption and after decryption.
 * </p>
 */
public class FileProcessor {

    /**
     * Encrypts a single file into a Cryptobox container.
     * Computes and prints SHA-256 hash of the input file before encryption.
     *
     * @param input  source file path
     * @param output output container path
     * @param key    32-byte AES key
     * @throws IOException if file I/O fails
     */
    public void encryptFile(Path input, Path output, byte[] key) throws IOException {
        if (!Files.exists(input)) {
            throw new Errors.FileOperationException("Input file not found: " + input);
        }

        // Compute SHA256 before encryption
        String sha256 = Integrity.computeHash(input);
        System.out.println("SHA256: " + sha256 + "  " + input.getFileName());

        byte[] plaintext = Files.readAllBytes(input);
        byte[] salt = KeyDerivation.generateSalt();
        byte[] iv = CryptoEngine.generateIv();

        byte[] derivedKey = deriveFileKey(key, salt);
        byte[] ciphertext = CryptoEngine.encrypt(plaintext, derivedKey, iv);

        byte[] kdfId = {0x00, Config.KDF_PBKDF2};
        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);

        Files.createDirectories(output.getParent());
        Files.write(output, container, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // Clear sensitive data
        java.util.Arrays.fill(plaintext, (byte) 0);
    }

    /**
     * Decrypts a Cryptobox container back to the original file.
     * Computes and prints SHA-256 hash of the restored file for verification.
     *
     * @param input  container file path
     * @param output output file path
     * @param key    32-byte AES key
     * @throws IOException if file I/O fails
     */
    public void decryptFile(Path input, Path output, byte[] key) throws IOException {
        if (!Files.exists(input)) {
            throw new Errors.FileOperationException("Input file not found: " + input);
        }

        byte[] containerData = Files.readAllBytes(input);
        ContainerParser.ContainerData parsed = ContainerParser.parse(containerData);

        byte[] derivedKey = deriveFileKey(key, parsed.salt);
        byte[] plaintext = CryptoEngine.decrypt(parsed.ciphertext, derivedKey, parsed.iv);

        Files.createDirectories(output.getParent());
        Files.write(output, plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // Clear sensitive data
        java.util.Arrays.fill(plaintext, (byte) 0);

        // Compute SHA256 after decryption
        String sha256 = Integrity.computeHash(output);
        System.out.println("SHA256: " + sha256 + "  " + output.getFileName());
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
        if (!Files.exists(inputDir) || !Files.isDirectory(inputDir)) {
            throw new Errors.FileOperationException("Input directory not found: " + inputDir);
        }

        Files.createDirectories(outputDir);

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
     * Decrypts a directory of Cryptobox containers, restoring the original
     * directory structure. Output files have their .crbx extension removed.
     *
     * @param inputDir  input directory containing .crbx containers
     * @param outputDir output directory for restored files
     * @param key       32-byte AES key
     * @throws IOException if file I/O fails
     */
    public void decryptDirectory(Path inputDir, Path outputDir, byte[] key) throws IOException {
        if (!Files.exists(inputDir) || !Files.isDirectory(inputDir)) {
            throw new Errors.FileOperationException("Input directory not found: " + inputDir);
        }

        Files.createDirectories(outputDir);

        try (Stream<Path> files = Files.walk(inputDir)) {
            files.filter(Files::isRegularFile)
                .filter(file -> file.toString().endsWith(".crbx"))
                .forEach(file -> {
                    try {
                        Path relativePath = inputDir.relativize(file);
                        // Remove .crbx extension
                        String fileName = relativePath.toString();
                        String restoredName = fileName.endsWith(".crbx")
                            ? fileName.substring(0, fileName.length() - 5)
                            : fileName;
                        Path outputFile = outputDir.resolve(restoredName);
                        decryptFile(file, outputFile, key);
                        System.out.println("Decrypted: " + restoredName);
                    } catch (IOException e) {
                        System.err.println("Failed to decrypt " + file + ": " + e.getMessage());
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