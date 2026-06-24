package com.cryptobox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SHA256 integrity verification via Integrity class.
 */
public class IntegrityTest {

    @TempDir
    Path tempDir;

    @Test
    public void testComputeHashFile() throws IOException {
        Path testFile = tempDir.resolve("test.txt");
        String content = "Test content for SHA256 hash computation.";
        Files.writeString(testFile, content, StandardCharsets.UTF_8);

        String hash = Integrity.computeHash(testFile);
        assertNotNull(hash, "Hash should not be null");
        assertEquals(64, hash.length(), "SHA256 hash should be 64 hex characters");
        assertTrue(hash.matches("[0-9A-F]+"), "Hash should be uppercase hex");
    }

    @Test
    public void testComputeHashByteArray() {
        byte[] data = "Test data for byte array hashing".getBytes(StandardCharsets.UTF_8);
        String hash = Integrity.computeHash(data);
        assertNotNull(hash, "Hash should not be null");
        assertEquals(64, hash.length(), "SHA256 hash should be 64 hex characters");
    }

    @Test
    public void testSameContentSameHash() throws IOException {
        Path file1 = tempDir.resolve("a.txt");
        Path file2 = tempDir.resolve("b.txt");
        String content = "Identical content for both files.";

        Files.writeString(file1, content, StandardCharsets.UTF_8);
        Files.writeString(file2, content, StandardCharsets.UTF_8);

        String hash1 = Integrity.computeHash(file1);
        String hash2 = Integrity.computeHash(file2);
        assertEquals(hash1, hash2, "Same content should produce same hash");
    }

    @Test
    public void testDifferentContentDifferentHash() throws IOException {
        Path file1 = tempDir.resolve("a.txt");
        Path file2 = tempDir.resolve("b.txt");

        Files.writeString(file1, "Content A", StandardCharsets.UTF_8);
        Files.writeString(file2, "Content B", StandardCharsets.UTF_8);

        String hash1 = Integrity.computeHash(file1);
        String hash2 = Integrity.computeHash(file2);
        assertNotEquals(hash1, hash2, "Different content should produce different hashes");
    }

    @Test
    public void testEmptyFileHash() throws IOException {
        Path emptyFile = tempDir.resolve("empty.txt");
        Files.writeString(emptyFile, "", StandardCharsets.UTF_8);

        String hash = Integrity.computeHash(emptyFile);
        assertNotNull(hash, "Empty file hash should not be null");
        assertEquals(64, hash.length(), "Empty file SHA256 should be 64 hex chars");

        // Known SHA256 of empty string
        assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                     hash, "SHA256 of empty file should match known value");
    }

    @Test
    public void testLargeFileHash() throws IOException {
        Path largeFile = tempDir.resolve("large.bin");
        byte[] data = new byte[5 * 1024 * 1024]; // 5MB
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 256);
        }
        Files.write(largeFile, data);

        String hash = Integrity.computeHash(largeFile);
        assertNotNull(hash);
        assertEquals(64, hash.length());
    }

    @Test
    public void testConsistencyWithJavaStandard() throws IOException, NoSuchAlgorithmException {
        Path testFile = tempDir.resolve("consistency.txt");
        String content = "Consistency check content.";
        Files.writeString(testFile, content, StandardCharsets.UTF_8);

        // Compute using our Integrity utility
        String ourHash = Integrity.computeHash(testFile);

        // Compute using standard Java MessageDigest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(content.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02X", b));
        }
        String standardHash = sb.toString();

        assertEquals(standardHash, ourHash, "Hash should match standard Java implementation");
    }

    @Test
    public void testByteArrayVsFileHash() throws IOException {
        Path testFile = tempDir.resolve("hash_compare.txt");
        String content = "Comparing file hash vs byte array hash.";
        Files.writeString(testFile, content, StandardCharsets.UTF_8);

        String fileHash = Integrity.computeHash(testFile);
        String byteHash = Integrity.computeHash(content.getBytes(StandardCharsets.UTF_8));

        assertEquals(fileHash, byteHash, "File hash vs byte array hash should match for same content");
    }

    @Test
    public void testHashDirectoryRecursive() throws IOException {
        // Create directory structure with files
        Path dir = tempDir.resolve("hashdir");
        Files.createDirectories(dir);
        Files.createDirectories(dir.resolve("sub"));

        Files.writeString(dir.resolve("f1.txt"), "File 1", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("f2.txt"), "File 2", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("sub").resolve("f3.txt"), "File 3", StandardCharsets.UTF_8);

        // Collect hashes of all files
        Set<String> hashes = new HashSet<>();
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.filter(Files::isRegularFile).sorted().forEach(p -> {
                try {
                    hashes.add(Integrity.computeHash(p));
                } catch (IOException e) {
                    fail("Failed to hash " + p + ": " + e.getMessage());
                }
            });
        }

        assertEquals(3, hashes.size(), "Should have 3 unique hashes for 3 different files");
    }

    @Test
    public void testHashDeterministic() throws IOException {
        Path testFile = tempDir.resolve("deterministic.txt");
        Files.writeString(testFile, "Deterministic test", StandardCharsets.UTF_8);

        String hash1 = Integrity.computeHash(testFile);
        String hash2 = Integrity.computeHash(testFile);
        String hash3 = Integrity.computeHash(testFile);

        assertEquals(hash1, hash2, "First and second hash should match");
        assertEquals(hash2, hash3, "Second and third hash should match");
    }

    @Test
    public void testFileNotFound() {
        Path nonExistent = tempDir.resolve("nonexistent.txt");
        assertThrows(IOException.class, () -> {
            Integrity.computeHash(nonExistent);
        }, "Hashing non-existent file should throw IOException");
    }

    @Test
    public void testHashAfterEncryptDecryptRoundTrip() throws IOException {
        // Create file
        Path inputFile = tempDir.resolve("roundtrip.txt");
        String content = "Round-trip integrity verification test.";
        Files.writeString(inputFile, content, StandardCharsets.UTF_8);

        // Get original hash
        String originalHash = Integrity.computeHash(inputFile);

        // Encrypt
        byte[] key = CryptoEngine.generateKey();
        Path encryptedFile = tempDir.resolve("roundtrip.crbx");
        FileProcessor processor = new FileProcessor();
        processor.encryptFile(inputFile, encryptedFile, key);

        // Decrypt
        Path decryptedFile = tempDir.resolve("roundtrip_restored.txt");
        processor.decryptFile(encryptedFile, decryptedFile, key);

        // Get decrypted hash
        String decryptedHash = Integrity.computeHash(decryptedFile);

        // Compare
        assertEquals(originalHash, decryptedHash,
            "SHA256 hash should match after encrypt-decrypt round-trip");

        // Clean up
        java.util.Arrays.fill(key, (byte) 0);
    }

    @Test
    public void testHashMultipleCallsPerformance() throws IOException {
        Path testFile = tempDir.resolve("perf_test.txt");
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            content.append("Line ").append(i).append("\n");
        }
        Files.writeString(testFile, content.toString(), StandardCharsets.UTF_8);

        // Call hash multiple times
        String firstHash = Integrity.computeHash(testFile);
        for (int i = 0; i < 10; i++) {
            assertEquals(firstHash, Integrity.computeHash(testFile),
                "Hash should be consistent across multiple calls");
        }
    }
}