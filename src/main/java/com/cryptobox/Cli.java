package com.cryptobox;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.concurrent.Callable;

/**
 * CLI command definitions using picocli.
 * <p>
 * Defines all subcommands: keygen, encrypt, decrypt, verify, hash.
 * All commands support --help and follow consistent error handling.
 * </p>
 */
@Command(
    name = "cryptobox",
    version = "Cryptobox Java v1.0.0",
    description = "A local file encryption CLI tool using AES-256-GCM.",
    mixinStandardHelpOptions = true,
    subcommands = {
        Cli.Keygen.class,
        Cli.Encrypt.class,
        Cli.Decrypt.class,
        Cli.Verify.class,
        Cli.Hash.class
    }
)
public class Cli implements Callable<Integer> {

    @Override
    public Integer call() {
        CommandLine.usage(this, System.out);
        return 0;
    }

    // ---------- keygen ----------

    @Command(
        name = "keygen",
        description = "Generate a random 32-byte AES-256 key and save to file",
        mixinStandardHelpOptions = true
    )
    public static class Keygen implements Callable<Integer> {
        @Option(
            names = {"-o", "--output"},
            description = "Output key file path",
            required = true
        )
        private String outputPath;

        @Override
        public Integer call() {
            try {
                byte[] key = CryptoEngine.generateKey();
                String encoded = Base64.getEncoder().encodeToString(key);
                Path output = Paths.get(outputPath);
                Files.createDirectories(output.getParent());
                Files.writeString(output, encoded + System.lineSeparator());
                // Clear key from memory
                java.util.Arrays.fill(key, (byte) 0);
                System.out.println("Key generated: " + output.toAbsolutePath());
                return 0;
            } catch (Exception e) {
                System.err.println("Error generating key: " + e.getMessage());
                return 1;
            }
        }
    }

    // ---------- encrypt ----------

    @Command(
        name = "encrypt",
        description = "Encrypt a file or directory using AES-256-GCM",
        mixinStandardHelpOptions = true
    )
    public static class Encrypt implements Callable<Integer> {
        @Option(
            names = {"-k", "--key"},
            description = "Path to the encryption key file"
        )
        private String keyPath;

        @Option(
            names = {"-p", "--password"},
            description = "Use password-based encryption (interactive prompt)"
        )
        private boolean usePassword;

        @Option(
            names = {"-i", "--input"},
            description = "Input file path",
            required = true
        )
        private String inputPath;

        @Option(
            names = {"-o", "--output"},
            description = "Output file path",
            required = true
        )
        private String outputPath;

        @Option(
            names = {"-r", "--recursive"},
            description = "Encrypt directory recursively"
        )
        private boolean recursive;

        @Option(
            names = {"--exclude"},
            description = "Exclude files matching pattern (comma-separated)"
        )
        private String excludePattern;

        @Override
        public Integer call() {
            try {
                Path input = Paths.get(inputPath);
                Path output = Paths.get(outputPath);

                if (usePassword) {
                    return encryptWithPassword(input, output);
                }

                if (keyPath == null) {
                    System.err.println("Either --key or --password must be specified.");
                    return 1;
                }

                byte[] key = loadKeyFromFile(keyPath);
                try {
                    FileProcessor processor = new FileProcessor();

                    if (Files.isDirectory(input) && recursive) {
                        processor.encryptDirectory(input, output, key, excludePattern);
                    } else if (Files.isDirectory(input)) {
                        System.err.println("Input is a directory. Use --recursive to encrypt directories.");
                        return 1;
                    } else {
                        processor.encryptFile(input, output, key);
                    }

                    System.out.println("Encryption completed.");
                    return 0;
                } finally {
                    clearKey(key);
                }
            } catch (Exception e) {
                System.err.println("Encryption failed: " + e.getMessage());
                return 1;
            }
        }

        /**
         * Handles password-based encryption using CryptoEngine and ContainerParser directly.
         * Password key derivation salt is stored in the container for decryption.
         */
        private int encryptWithPassword(Path input, Path output) throws IOException {
            java.io.Console console = System.console();
            if (console == null) {
                System.err.println("No console available for password input");
                return 1;
            }

            char[] password1 = console.readPassword("Enter password: ");
            char[] password2 = console.readPassword("Confirm password: ");

            if (!java.util.Arrays.equals(password1, password2)) {
                java.util.Arrays.fill(password1, '\0');
                java.util.Arrays.fill(password2, '\0');
                System.err.println("Passwords do not match");
                return 1;
            }
            java.util.Arrays.fill(password2, '\0');

            try {
                // Derive key from password with a fresh salt
                byte[] salt = KeyDerivation.generateSalt();
                byte[] derivedKey = KeyDerivation.deriveKeyFromPassword(password1, salt);

                try {
                    if (!Files.exists(input)) {
                        System.err.println("Input file not found: " + input);
                        return 1;
                    }

                    byte[] plaintext = Files.readAllBytes(input);
                    byte[] iv = CryptoEngine.generateIv();
                    byte[] ciphertext = CryptoEngine.encrypt(plaintext, derivedKey, iv);
                    byte[] kdfId = {0x00, Config.KDF_PBKDF2};
                    byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);

                    Files.createDirectories(output.getParent());
                    Files.write(output, container);

                    System.out.println("Encryption completed.");
                    return 0;
                } finally {
                    clearKey(derivedKey);
                }
            } finally {
                java.util.Arrays.fill(password1, '\0');
            }
        }
    }

    // ---------- decrypt ----------

    @Command(
        name = "decrypt",
        description = "Decrypt a Cryptobox container file",
        mixinStandardHelpOptions = true
    )
    public static class Decrypt implements Callable<Integer> {
        @Option(
            names = {"-k", "--key"},
            description = "Path to the decryption key file"
        )
        private String keyPath;

        @Option(
            names = {"-p", "--password"},
            description = "Use password-based decryption (interactive prompt)"
        )
        private boolean usePassword;

        @Option(
            names = {"-i", "--input"},
            description = "Input container file",
            required = true
        )
        private String inputPath;

        @Option(
            names = {"-o", "--output"},
            description = "Output file path",
            required = true
        )
        private String outputPath;

        @Override
        public Integer call() {
            try {
                Path input = Paths.get(inputPath);
                Path output = Paths.get(outputPath);

                if (usePassword) {
                    return decryptWithPassword(input, output);
                }

                if (keyPath == null) {
                    System.err.println("Either --key or --password must be specified.");
                    return 1;
                }

                byte[] key = loadKeyFromFile(keyPath);
                try {
                    FileProcessor processor = new FileProcessor();
                    processor.decryptFile(input, output, key);
                    System.out.println("Decryption completed.");
                    return 0;
                } finally {
                    clearKey(key);
                }
            } catch (Errors.DecryptionException e) {
                System.err.println("Decryption failed: wrong key or corrupted data");
                return 1;
            } catch (Exception e) {
                System.err.println("Decryption failed: " + e.getMessage());
                return 1;
            }
        }

        /**
         * Handles password-based decryption by reading the salt from the container
         * and deriving the key from the password and that salt.
         */
        private int decryptWithPassword(Path input, Path output) throws IOException {
            java.io.Console console = System.console();
            if (console == null) {
                System.err.println("No console available for password input");
                return 1;
            }

            if (!Files.exists(input)) {
                System.err.println("Input file not found: " + input);
                return 1;
            }

            // Read container to get the salt
            byte[] containerData = Files.readAllBytes(input);
            ContainerParser.ContainerData parsed;
            try {
                parsed = ContainerParser.parse(containerData);
            } catch (Errors.ContainerFormatException e) {
                System.err.println("Decryption failed: not a valid Cryptobox container");
                return 1;
            }

            char[] password = console.readPassword("Enter decryption password: ");
            try {
                // Derive key from password + salt from container (same salt used during encryption)
                byte[] derivedKey = KeyDerivation.deriveKeyFromPassword(password, parsed.salt);
                try {
                    byte[] plaintext = CryptoEngine.decrypt(parsed.ciphertext, derivedKey, parsed.iv);
                    Files.createDirectories(output.getParent());
                    Files.write(output, plaintext);
                    System.out.println("Decryption completed.");
                    return 0;
                } finally {
                    clearKey(derivedKey);
                }
            } catch (Errors.DecryptionException e) {
                System.err.println("Decryption failed: wrong key or corrupted data");
                return 1;
            } finally {
                java.util.Arrays.fill(password, '\0');
            }
        }
    }

    // ---------- verify ----------

    @Command(
        name = "verify",
        description = "Verify Cryptobox container format and integrity",
        mixinStandardHelpOptions = true
    )
    public static class Verify implements Callable<Integer> {
        @Option(
            names = {"-i", "--input"},
            description = "Input container file",
            required = true
        )
        private String inputPath;

        @Option(
            names = {"-k", "--key"},
            description = "Key file for tag verification (optional)"
        )
        private String keyPath;

        @Override
        public Integer call() {
            try {
                Path input = Paths.get(inputPath);
                byte[] containerData = Files.readAllBytes(input);
                ContainerParser.parse(containerData);
                System.out.println("Container format: valid");

                if (keyPath != null) {
                    byte[] key = loadKeyFromFile(keyPath);
                    try {
                        ContainerParser.verifyTag(containerData, key);
                        System.out.println("Integrity (GCM tag): valid");
                    } finally {
                        clearKey(key);
                    }
                }

                return 0;
            } catch (Errors.ContainerFormatException e) {
                System.err.println("Verification failed: " + e.getMessage());
                return 1;
            } catch (Exception e) {
                System.err.println("Verification failed: " + e.getMessage());
                return 1;
            }
        }
    }

    // ---------- hash ----------

    @Command(
        name = "hash",
        description = "Compute SHA256 hash of a file or directory",
        mixinStandardHelpOptions = true
    )
    public static class Hash implements Callable<Integer> {
        @Option(
            names = {"-i", "--input"},
            description = "Input file or directory path",
            required = true
        )
        private String inputPath;

        @Option(
            names = {"-a", "--algorithm"},
            description = "Hash algorithm (default: SHA256)",
            defaultValue = "SHA256"
        )
        private String algorithm;

        @Override
        public Integer call() {
            try {
                Path input = Paths.get(inputPath);
                if (Files.isDirectory(input)) {
                    Files.walk(input)
                        .filter(Files::isRegularFile)
                        .sorted()
                        .forEach(file -> {
                            try {
                                String hash = Integrity.computeHash(file);
                                System.out.println(hash + "  " + input.relativize(file));
                            } catch (IOException e) {
                                System.err.println("Error hashing " + file + ": " + e.getMessage());
                            }
                        });
                } else {
                    String hash = Integrity.computeHash(input);
                    System.out.println(hash + "  " + input.getFileName());
                }
                return 0;
            } catch (Exception e) {
                System.err.println("Hash failed: " + e.getMessage());
                return 1;
            }
        }
    }

    // ---------- Utility Methods ----------

    /**
     * Loads a Base64-encoded AES-256 key from a file.
     *
     * @param keyPath path to the key file
     * @return the decoded 32-byte key
     * @throws IOException if file cannot be read
     */
    static byte[] loadKeyFromFile(String keyPath) throws IOException {
        Path path = Paths.get(keyPath);
        if (!Files.exists(path)) {
            throw new Errors.FileOperationException("Key file not found: " + keyPath);
        }
        String content = Files.readString(path).trim();
        return Base64.getDecoder().decode(content);
    }

    /**
     * Securely clears a byte array by overwriting with zeros.
     *
     * @param key the key material to clear
     */
    static void clearKey(byte[] key) {
        if (key != null) {
            java.util.Arrays.fill(key, (byte) 0);
        }
    }
}