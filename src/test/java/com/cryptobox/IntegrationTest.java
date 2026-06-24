package com.cryptobox;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests covering end-to-end encryption/decryption workflows,
 * large file performance, and concurrent multi-threaded operations.
 */
public class IntegrationTest {

    @TempDir
    Path tempDir;

    private FileProcessor processor;
    private byte[] testKey;

    @BeforeEach
    public void setUp() {
        processor = new FileProcessor();
        testKey = new byte[32];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(testKey);
    }

    @AfterEach
    public void tearDown() {
        if (testKey != null) {
            Arrays.fill(testKey, (byte) 0);
        }
    }

    // ──────────────────────────────────────────────
    // End-to-End Directory Round-Trip
    // ──────────────────────────────────────────────

    @Test
    public void testEndToEndDirectoryRoundTrip() throws IOException {
        // Create a complex directory structure
        Path sourceDir = tempDir.resolve("source");
        Path encryptDir = tempDir.resolve("encrypted");
        Path restoreDir = tempDir.resolve("restored");

        createComplexDirectoryStructure(sourceDir);

        // Encrypt all files recursively
        processor.encryptDirectory(sourceDir, encryptDir, testKey, null);

        // Verify all .crbx files exist
        assertTrue(Files.exists(encryptDir.resolve("root.txt.crbx")));
        assertTrue(Files.exists(encryptDir.resolve("sub1").resolve("sub1_a.txt.crbx")));
        assertTrue(Files.exists(encryptDir.resolve("sub1").resolve("sub1_b.txt.crbx")));
        assertTrue(Files.exists(encryptDir.resolve("sub2").resolve("sub2_a.txt.crbx")));
        assertTrue(Files.exists(encryptDir.resolve("sub2").resolve("nested").resolve("deep.txt.crbx")));

        // Decrypt all files recursively
        processor.decryptDirectory(encryptDir, restoreDir, testKey);

        // Verify restored content matches originals
        assertEquals("Root file content", Files.readString(restoreDir.resolve("root.txt"), StandardCharsets.UTF_8));
        assertEquals("Sub1 A content", Files.readString(restoreDir.resolve("sub1").resolve("sub1_a.txt"), StandardCharsets.UTF_8));
        assertEquals("Sub1 B content", Files.readString(restoreDir.resolve("sub1").resolve("sub1_b.txt"), StandardCharsets.UTF_8));
        assertEquals("Sub2 A content", Files.readString(restoreDir.resolve("sub2").resolve("sub2_a.txt"), StandardCharsets.UTF_8));
        assertEquals("Deep nested content", Files.readString(restoreDir.resolve("sub2").resolve("nested").resolve("deep.txt"), StandardCharsets.UTF_8));
    }

    @Test
    public void testEndToEndDirectoryWithMixedFileTypes() throws IOException {
        Path sourceDir = tempDir.resolve("mixed_source");
        Path encryptDir = tempDir.resolve("mixed_encrypted");
        Path restoreDir = tempDir.resolve("mixed_restored");

        Files.createDirectories(sourceDir);

        // Text file
        Files.writeString(sourceDir.resolve("document.txt"), "Plain text document", StandardCharsets.UTF_8);

        // JSON-like content
        String json = "{\"name\": \"test\", \"value\": 42, \"nested\": {\"flag\": true}}";
        Files.writeString(sourceDir.resolve("config.json"), json, StandardCharsets.UTF_8);

        // Binary file
        byte[] binaryContent = new byte[512];
        new SecureRandom().nextBytes(binaryContent);
        Files.write(sourceDir.resolve("data.bin"), binaryContent);

        // Empty file
        Files.writeString(sourceDir.resolve("empty.txt"), "", StandardCharsets.UTF_8);

        // Unicode file
        Files.writeString(sourceDir.resolve("unicode_测试.txt"), "Unicode: 你好世界 €", StandardCharsets.UTF_8);

        // Encrypt
        processor.encryptDirectory(sourceDir, encryptDir, testKey, null);

        // Verify all files encrypted (even the empty one)
        assertEquals(5, countFiles(encryptDir), "All 5 files should be encrypted");

        // Decrypt
        processor.decryptDirectory(encryptDir, restoreDir, testKey);

        // Verify content
        assertEquals("Plain text document",
            Files.readString(restoreDir.resolve("document.txt"), StandardCharsets.UTF_8));
        assertEquals(json,
            Files.readString(restoreDir.resolve("config.json"), StandardCharsets.UTF_8));
        assertArrayEquals(binaryContent,
            Files.readAllBytes(restoreDir.resolve("data.bin")));
        assertEquals("",
            Files.readString(restoreDir.resolve("empty.txt"), StandardCharsets.UTF_8));
        assertEquals("Unicode: 你好世界 €",
            Files.readString(restoreDir.resolve("unicode_测试.txt"), StandardCharsets.UTF_8));
    }

    // ──────────────────────────────────────────────
    // Large File Performance Test (>10MB)
    // ──────────────────────────────────────────────

    @Test
    public void testLargeFileEncryptDecryptPerformance() throws IOException {
        // Create a ~10MB file with patterned data
        Path inputFile = tempDir.resolve("large_10mb.dat");
        int size = 10 * 1024 * 1024; // 10 MB
        byte[] largeData = new byte[size];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(largeData);
        Files.write(inputFile, largeData);

        Path encryptedFile = tempDir.resolve("large_10mb.crbx");
        Path decryptedFile = tempDir.resolve("large_10mb_restored.dat");

        // Time the encryption
        long encryptStart = System.nanoTime();
        processor.encryptFile(inputFile, encryptedFile, testKey);
        long encryptDuration = System.nanoTime() - encryptStart;

        assertTrue(Files.exists(encryptedFile), "Encrypted 10MB file should exist");
        double encryptSeconds = encryptDuration / 1_000_000_000.0;
        System.out.println("Encrypted 10MB file in " + String.format("%.2f", encryptSeconds) + " seconds");

        // Time the decryption
        long decryptStart = System.nanoTime();
        processor.decryptFile(encryptedFile, decryptedFile, testKey);
        long decryptDuration = System.nanoTime() - decryptStart;

        assertTrue(Files.exists(decryptedFile), "Decrypted 10MB file should exist");
        double decryptSeconds = decryptDuration / 1_000_000_000.0;
        System.out.println("Decrypted 10MB file in " + String.format("%.2f", decryptSeconds) + " seconds");

        // Verify content
        byte[] restoredData = Files.readAllBytes(decryptedFile);
        assertArrayEquals(largeData, restoredData, "10MB file round-trip should preserve content");

        // Verify performance is reasonable (should complete in reasonable time)
        double totalSeconds = encryptSeconds + decryptSeconds;
        assertTrue(totalSeconds < 120.0, "Large file operations should complete within 2 minutes");
    }

    @Test
    public void testVeryLargeFileEncryptDecrypt() throws IOException {
        // Create a ~50MB file to stress test the encryption pipeline
        Path inputFile = tempDir.resolve("very_large_50mb.dat");
        int size = 50 * 1024 * 1024; // 50 MB
        byte[] largeData = new byte[size];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(largeData);
        Files.write(inputFile, largeData);

        Path encryptedFile = tempDir.resolve("very_large_50mb.crbx");
        Path decryptedFile = tempDir.resolve("very_large_50mb_restored.dat");

        long start = System.nanoTime();
        processor.encryptFile(inputFile, encryptedFile, testKey);
        processor.decryptFile(encryptedFile, decryptedFile, testKey);
        long duration = System.nanoTime() - start;

        byte[] restoredData = Files.readAllBytes(decryptedFile);
        assertArrayEquals(largeData, restoredData, "50MB file round-trip should preserve content");

        double seconds = duration / 1_000_000_000.0;
        System.out.println("Processed 50MB file in " + String.format("%.2f", seconds) + " seconds");
        assertTrue(seconds < 300.0, "50MB file operation should complete within 5 minutes");
    }

    // ──────────────────────────────────────────────
    // Concurrent Multi-Threaded Encryption
    // ──────────────────────────────────────────────

    @Test
    public void testConcurrentEncryptionMultipleFiles() throws InterruptedException {
        int numFiles = 20;
        int numThreads = 4;
        Path sourceDir = tempDir.resolve("concurrent_source");
        Path encryptDir = tempDir.resolve("concurrent_encrypted");

        assertTrue(sourceDir.toFile().mkdirs());

        // Create test files
        List<Path> inputFiles = new ArrayList<>();
        SecureRandom rng = new SecureRandom();
        for (int i = 0; i < numFiles; i++) {
            Path file = sourceDir.resolve("file_" + i + ".txt");
            byte[] content = new byte[1024 * (i + 1)]; // Varying sizes
            rng.nextBytes(content);
            try {
                Files.write(file, content);
            } catch (IOException e) {
                fail("Failed to create test file: " + e.getMessage());
            }
            inputFiles.add(file);
        }

        assertTrue(encryptDir.toFile().mkdirs());

        // Encrypt files concurrently
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numFiles);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);
        List<String> errors = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < numFiles; i++) {
            final int index = i;
            final Path inputFile = inputFiles.get(i);
            final Path outputFile = encryptDir.resolve("file_" + index + ".crbx");
            final byte[] threadKey = Arrays.copyOf(testKey, 32);

            executor.submit(() -> {
                try {
                    FileProcessor fp = new FileProcessor();
                    fp.encryptFile(inputFile, outputFile, threadKey);
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                    errors.add("File " + index + ": " + e.getMessage());
                } finally {
                    Arrays.fill(threadKey, (byte) 0);
                    latch.countDown();
                }
            });
        }

        // Wait for all threads to finish (with timeout)
        boolean completed = latch.await(5, TimeUnit.MINUTES);
        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.MINUTES);

        assertTrue(completed, "All concurrent encryption tasks should complete within timeout");
        assertEquals(numFiles, successCount.get(), "All " + numFiles + " files should be encrypted successfully");
        assertEquals(0, failureCount.get(), "No encryption tasks should fail. Errors: " + errors);
    }

    @Test
    public void testConcurrentEncryptDecryptRoundTrip() throws InterruptedException, IOException {
        int numFiles = 10;
        int numThreads = 4;
        Path sourceDir = tempDir.resolve("roundtrip_source");
        Path encryptDir = tempDir.resolve("roundtrip_encrypted");
        Path restoreDir = tempDir.resolve("roundtrip_restored");

        assertTrue(sourceDir.toFile().mkdirs());
        assertTrue(encryptDir.toFile().mkdirs());
        assertTrue(restoreDir.toFile().mkdirs());

        // Create test files with known content
        List<Path> inputFiles = new ArrayList<>();
        List<String> expectedContents = new ArrayList<>();
        for (int i = 0; i < numFiles; i++) {
            Path file = sourceDir.resolve("concurrent_" + i + ".txt");
            String content = "Concurrent test content for file " + i +
                " with some extra data to make it more interesting: " +
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Files.writeString(file, content, StandardCharsets.UTF_8);
            inputFiles.add(file);
            expectedContents.add(content);
        }

        // Concurrently encrypt all files
        ExecutorService encryptExecutor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch encryptLatch = new CountDownLatch(numFiles);
        AtomicInteger encryptSuccess = new AtomicInteger(0);

        for (int i = 0; i < numFiles; i++) {
            final int index = i;
            final Path inputFile = inputFiles.get(i);
            final Path outputFile = encryptDir.resolve("concurrent_" + index + ".crbx");
            final byte[] threadKey = Arrays.copyOf(testKey, 32);

            encryptExecutor.submit(() -> {
                try {
                    FileProcessor fp = new FileProcessor();
                    fp.encryptFile(inputFile, outputFile, threadKey);
                    encryptSuccess.incrementAndGet();
                } catch (Exception e) {
                    System.err.println("Encrypt failed for file " + index + ": " + e.getMessage());
                } finally {
                    Arrays.fill(threadKey, (byte) 0);
                    encryptLatch.countDown();
                }
            });
        }

        assertTrue(encryptLatch.await(3, TimeUnit.MINUTES), "Encryption should complete");
        encryptExecutor.shutdown();
        encryptExecutor.awaitTermination(30, TimeUnit.SECONDS);
        assertEquals(numFiles, encryptSuccess.get(), "All encrypts should succeed");

        // Concurrently decrypt all files
        ExecutorService decryptExecutor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch decryptLatch = new CountDownLatch(numFiles);
        AtomicInteger decryptSuccess = new AtomicInteger(0);
        List<Path> outputFiles = new ArrayList<>();

        for (int i = 0; i < numFiles; i++) {
            final int index = i;
            final Path outputFile = restoreDir.resolve("concurrent_" + i + ".txt");
            outputFiles.add(outputFile);
        }

        for (int i = 0; i < numFiles; i++) {
            final int index = i;
            final Path encryptedFile = encryptDir.resolve("concurrent_" + index + ".crbx");
            final Path outputFile = outputFiles.get(i);
            final byte[] threadKey = Arrays.copyOf(testKey, 32);

            decryptExecutor.submit(() -> {
                try {
                    FileProcessor fp = new FileProcessor();
                    fp.decryptFile(encryptedFile, outputFile, threadKey);
                    decryptSuccess.incrementAndGet();
                } catch (Exception e) {
                    System.err.println("Decrypt failed for file " + index + ": " + e.getMessage());
                } finally {
                    Arrays.fill(threadKey, (byte) 0);
                    decryptLatch.countDown();
                }
            });
        }

        assertTrue(decryptLatch.await(3, TimeUnit.MINUTES), "Decryption should complete");
        decryptExecutor.shutdown();
        decryptExecutor.awaitTermination(30, TimeUnit.SECONDS);
        assertEquals(numFiles, decryptSuccess.get(), "All decrypts should succeed");

        // Verify all restored content
        for (int i = 0; i < numFiles; i++) {
            Path restoredFile = outputFiles.get(i);
            assertTrue(Files.exists(restoredFile), "Restored file " + i + " should exist");
            String restoredContent = Files.readString(restoredFile, StandardCharsets.UTF_8);
            assertEquals(expectedContents.get(i), restoredContent,
                "Concurrent round-trip file " + i + " content should match");
        }
    }

    @Test
    public void testConcurrentEncryptionWithSameFile() throws InterruptedException {
        // Test that the same file can be encrypted multiple times (producing different ciphertexts)
        Path inputFile = tempDir.resolve("shared.txt");
        try {
            Files.writeString(inputFile, "Shared content for concurrent encryption test", StandardCharsets.UTF_8);
        } catch (IOException e) {
            fail("Failed to create shared test file");
        }

        int numOperations = 10;
        ExecutorService executor = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(numOperations);
        AtomicInteger successCount = new AtomicInteger(0);

        for (int i = 0; i < numOperations; i++) {
            final int index = i;
            final Path outputFile = tempDir.resolve("shared_" + index + ".crbx");
            final byte[] threadKey = Arrays.copyOf(testKey, 32);

            executor.submit(() -> {
                try {
                    FileProcessor fp = new FileProcessor();
                    fp.encryptFile(inputFile, outputFile, threadKey);
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    System.err.println("Shared encrypt " + index + " failed: " + e.getMessage());
                } finally {
                    Arrays.fill(threadKey, (byte) 0);
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(2, TimeUnit.MINUTES), "All shared encryptions should complete");
        executor.shutdown();
        executor.awaitTermination(30, TimeUnit.SECONDS);
        assertEquals(numOperations, successCount.get(), "All shared encryptions should succeed");

        // Decrypt each and verify same content
        for (int i = 0; i < numOperations; i++) {
            Path encryptedFile = tempDir.resolve("shared_" + i + ".crbx");
            Path decryptedFile = tempDir.resolve("shared_" + i + "_restored.txt");
            try {
                processor.decryptFile(encryptedFile, decryptedFile, testKey);
                String content = Files.readString(decryptedFile, StandardCharsets.UTF_8);
                assertEquals("Shared content for concurrent encryption test", content,
                    "Decrypted content from operation " + i + " should match");
            } catch (IOException e) {
                fail("Decrypt of shared_" + i + " failed: " + e.getMessage());
            }
        }
    }

    // ──────────────────────────────────────────────
    // End-to-End Integrity Check
    // ──────────────────────────────────────────────

    @Test
    public void testEndToEndIntegrityChain() throws IOException {
        // Encrypt a file, verify SHA256 before and after
        Path inputFile = tempDir.resolve("integrity_test.txt");
        String content = "Integrity chain test data for Cryptobox verification";
        Files.writeString(inputFile, content, StandardCharsets.UTF_8);

        // Compute SHA256 before encryption
        String originalHash = Integrity.computeHash(inputFile);

        Path encryptedFile = tempDir.resolve("integrity.crbx");
        processor.encryptFile(inputFile, encryptedFile, testKey);

        // Decrypt and verify
        Path decryptedFile = tempDir.resolve("integrity_restored.txt");
        processor.decryptFile(encryptedFile, decryptedFile, testKey);

        // Compute SHA256 after decryption
        String restoredHash = Integrity.computeHash(decryptedFile);

        assertEquals(originalHash, restoredHash,
            "SHA256 hash before encryption and after decryption should match");
    }

    // ──────────────────────────────────────────────
    // Cryptobox Container Verification Flow
    // ──────────────────────────────────────────────

    @Test
    public void testContainerVerificationEndToEnd() throws IOException {
        // Encrypt then verify the container
        Path inputFile = tempDir.resolve("verify_me.txt");
        Files.writeString(inputFile, "Container verification test", StandardCharsets.UTF_8);

        Path encryptedFile = tempDir.resolve("verify_me.crbx");
        processor.encryptFile(inputFile, encryptedFile, testKey);

        // Read container data and parse it for verification
        byte[] containerData = Files.readAllBytes(encryptedFile);
        ContainerParser.ContainerData parsed = ContainerParser.parse(containerData);

        assertNotNull(parsed, "Parsed container should not be null");
        assertNotNull(parsed.salt, "Salt should be present");
        assertNotNull(parsed.iv, "IV should be present");
        assertNotNull(parsed.ciphertext, "Ciphertext should be present");
        assertTrue(parsed.salt.length > 0, "Salt should not be empty");
        assertTrue(parsed.iv.length > 0, "IV should not be empty");
        assertTrue(parsed.ciphertext.length > 0, "Ciphertext should not be empty");
    }

    // ──────────────────────────────────────────────
    // Password-Based Round Trip
    // ──────────────────────────────────────────────

    @Test
    public void testPasswordBasedEncryptDecrypt() throws IOException {
        // This test simulates password-based encryption/decryption
        // by using KeyDerivation to derive a key from a password.
        Path inputFile = tempDir.resolve("password_test.txt");
        String content = "Password-protected content";
        Files.writeString(inputFile, content, StandardCharsets.UTF_8);

        char[] password = "MySecureP@ssw0rd!".toCharArray();
        byte[] salt = KeyDerivation.generateSalt();

        // Derive key from password (use fresh char array for each call since it gets cleared)
        byte[] derivedKey;
        try {
            derivedKey = KeyDerivation.deriveKeyWithArgon2id("MySecureP@ssw0rd!".toCharArray(), salt);
        } catch (Exception e) {
            // Fall back to PBKDF2 if Argon2id is not available
            derivedKey = KeyDerivation.deriveKeyWithPbkdf2("MySecureP@ssw0rd!".toCharArray(), salt);
        }

        Path encryptedFile = tempDir.resolve("password_test.crbx");
        processor.encryptFile(inputFile, encryptedFile, derivedKey);

        // Decrypt with same derived key
        Path decryptedFile = tempDir.resolve("password_test_restored.txt");
        processor.decryptFile(encryptedFile, decryptedFile, derivedKey);

        // Verify content matches
        String restoredContent = Files.readString(decryptedFile, StandardCharsets.UTF_8);
        assertEquals(content, restoredContent, "Password-based round-trip should work");

        // Clear sensitive data
        Arrays.fill(derivedKey, (byte) 0);
    }

    @Test
    public void testPasswordWithWrongPassword() throws IOException {
        Path inputFile = tempDir.resolve("wrong_pw.txt");
        Files.writeString(inputFile, "Wrong password test", StandardCharsets.UTF_8);

        byte[] salt = KeyDerivation.generateSalt();

        byte[] correctKey = KeyDerivation.deriveKeyWithPbkdf2("CorrectP@ss".toCharArray(), salt);

        Path encryptedFile = tempDir.resolve("wrong_pw.crbx");
        processor.encryptFile(inputFile, encryptedFile, correctKey);

        // Try with wrong password
        byte[] wrongKey = KeyDerivation.deriveKeyWithPbkdf2("WrongP@ss".toCharArray(), salt);

        Path decryptedFile = tempDir.resolve("wrong_pw_fail.txt");
        assertThrows(Errors.DecryptionException.class, () -> {
            processor.decryptFile(encryptedFile, decryptedFile, wrongKey);
        }, "Decryption with wrong password should fail");

        Arrays.fill(correctKey, (byte) 0);
        Arrays.fill(wrongKey, (byte) 0);
    }

    // ──────────────────────────────────────────────
    // Empty File Edge Cases
    // ──────────────────────────────────────────────

    @Test
    public void testEmptyDirectoryEncryptDecrypt() throws IOException {
        Path emptyDir = tempDir.resolve("empty_dir");
        Path encryptDir = tempDir.resolve("encrypted_empty");
        Path restoreDir = tempDir.resolve("restored_empty");

        Files.createDirectories(emptyDir);
        Files.createDirectories(encryptDir);
        Files.createDirectories(restoreDir);

        // Encrypt an empty directory (should produce no output files)
        processor.encryptDirectory(emptyDir, encryptDir, testKey, null);
        assertEquals(0, countFiles(encryptDir), "Empty directory should produce no encrypted files");

        // Decrypt an empty encrypted directory (should produce no output files)
        processor.decryptDirectory(encryptDir, restoreDir, testKey);
        assertEquals(0, countFiles(restoreDir), "Empty encrypted directory should produce no decrypted files");
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    private void createComplexDirectoryStructure(Path baseDir) throws IOException {
        Files.createDirectories(baseDir);
        Files.createDirectories(baseDir.resolve("sub1"));
        Files.createDirectories(baseDir.resolve("sub2").resolve("nested"));

        Files.writeString(baseDir.resolve("root.txt"), "Root file content", StandardCharsets.UTF_8);
        Files.writeString(baseDir.resolve("sub1").resolve("sub1_a.txt"), "Sub1 A content", StandardCharsets.UTF_8);
        Files.writeString(baseDir.resolve("sub1").resolve("sub1_b.txt"), "Sub1 B content", StandardCharsets.UTF_8);
        Files.writeString(baseDir.resolve("sub2").resolve("sub2_a.txt"), "Sub2 A content", StandardCharsets.UTF_8);
        Files.writeString(baseDir.resolve("sub2").resolve("nested").resolve("deep.txt"), "Deep nested content", StandardCharsets.UTF_8);
    }

    private long countFiles(Path directory) throws IOException {
        try (Stream<Path> files = Files.walk(directory)) {
            return files.filter(Files::isRegularFile).count();
        }
    }
}