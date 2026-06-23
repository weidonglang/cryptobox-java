package com.cryptobox;

import picocli.CommandLine;

/**
 * Cryptobox Java - A local file encryption CLI tool.
 * <p>
 * Uses AES-256-GCM for authenticated encryption, supports key derivation
 * via Argon2id/PBKDF2, directory recursion, and integrity verification.
 * Designed for offline personal data protection.
 * </p>
 */
public final class Cryptobox {

    private Cryptobox() {
        // Utility class - prevent instantiation
    }

    /**
     * Application entry point.
     *
     * @param args command-line arguments passed to the CLI
     */
    public static void main(String[] args) {
        System.exit(new CommandLine(new Cli()).execute(args));
    }
}