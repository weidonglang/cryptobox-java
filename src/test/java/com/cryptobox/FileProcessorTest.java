package com.cryptobox;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for FileProcessor encryption and decryption operations.
 * Covers single file, directory recursive, edge cases, and integrity verification.
 */
public class FileProcessorTest {

    @TempDir
    Path tempDir;

    private FileProcessor processor;
    private byte[] testKey;

    @BeforeEach
    public void setUp() {
        processor = new FileProcessor();
        testKey = new byte[32];
        // Use a fixed test key for reproducibility
        for (int i = 0; i < 32; i++) {
            testKey[i] = (byte) (i + 1);
        }
    }

    @AfterEach
    public void tearDown() {
        // Clear key from memory
        if (testKey != null) {
            Arrays.fill(testKey, (byte) 0);
        }
    }

    @Test
    public void testEncryptDecryptSmallFile() throws IOException {
        // Create a small test file
        Path inputFile = tempDir.resolve("hello.txt");
        String content = "Hello, Cryptobox! This is a test message for AES-256-GCM encryption.";
        Files.writeString(inputFile, content, StandardCharsets.UTF_8);

        Path encryptedFile = tempDir.resolve("hello.crbx");
        Path decryptedFile = tempDir.resolve("hello_restored.txt");

        // Encrypt
        processor.encryptFile(inputFile, encryptedFile, testKey);
        assertTrue(Files.exists(encryptedFile), "Encrypted file should exist");
        assertTrue(Files.size(encryptedFile) > 0, "Encrypted file should not be empty");

        // Decrypt
        processor.decryptFile(encryptedFile, decryptedFile, testKey);
        assertTrue(Files.exists(decryptedFile), "Decrypted file should exist");

        // Verify content matches
        String decryptedContent = Files.readString(decryptedFile, StandardCharsets.UTF_8);
        assertEquals(content, decryptedContent, "Decrypted content should match original");
    }

    @Test
    public void testEncryptDecryptEmptyFile() throws IOException {
        Path inputFile = tempDir.resolve("empty.txt");
        Files.writeString(inputFile, "", StandardCharsets.UTF_8);

        Path encryptedFile = tempDir.resolve("empty.crbx");
        Path decryptedFile = tempDir.resolve("empty_restored.txt");

        processor.encryptFile(inputFile, encryptedFile, testKey);
        processor.decryptFile(encryptedFile, decryptedFile, testKey);

        String decryptedContent = Files.readString(decryptedFile, StandardCharsets.UTF_8);
        assertEquals("", decryptedContent, "Empty file round-trip should preserve content");
    }

    @Test
    public void testEncryptDecryptLargeFile() throws IOException {
        // Create a ~1MB test file
        Path inputFile = tempDir.resolve("large.dat");
        byte[] largeData = new byte[1024 * 1024];
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte) (i % 256);
        }
        Files.write(inputFile, largeData);

        Path encryptedFile = tempDir.resolve("large.crbx");
        Path decryptedFile = tempDir.resolve("large_restored.dat");

        processor.encryptFile(inputFile, encryptedFile, testKey);
        processor.decryptFile(encryptedFile, decryptedFile, testKey);

        byte[] restoredData = Files.readAllBytes(decryptedFile);
        assertArrayEquals(largeData, restoredData, "Large file round-trip should preserve content");
    }

    @Test
    public void testDecryptWithWrongKey() throws IOException {
        Path inputFile = tempDir.resolve("secret.txt");
        Files.writeString(inputFile, "Top secret data", StandardCharsets.UTF_8);

        Path encryptedFile = tempDir.resolve("secret.crbx");
        processor.encryptFile(inputFile, encryptedFile, testKey);

        Path decryptedFile = tempDir.resolve("secret_restored.txt");

        // Use a wrong key
        byte[] wrongKey = new byte[32];
        Arrays.fill(wrongKey, (byte) 0xAB);

        assertThrows(Errors.DecryptionException.class, () -> {
            processor.decryptFile(encryptedFile, decryptedFile, wrongKey);
        }, "Decrypting with wrong key should throw DecryptionException");

        // Clean up wrong key
        Arrays.fill(wrongKey, (byte) 0);
    }

    @Test
    public void testEncryptDecryptFileWithUnicodeName() throws IOException {
        String unicodeFileName = "测试文件_Ünicöde_文件.txt";
        Path inputFile = tempDir.resolve(unicodeFileName);
        String content = "Unicode content: 你好世界 ÄÖÜ";
        Files.writeString(inputFile, content, StandardCharsets.UTF_8);

        Path encryptedFile = tempDir.resolve(unicodeFileName + ".crbx");
        Path decryptedFile = tempDir.resolve("unicode_restored.txt");

        processor.encryptFile(inputFile, encryptedFile, testKey);
        assertTrue(Files.exists(encryptedFile), "Encrypted file with Unicode name should exist");

        processor.decryptFile(encryptedFile, decryptedFile, testKey);
        String decryptedContent = Files.readString(decryptedFile, StandardCharsets.UTF_8);
        assertEquals(content, decryptedContent, "Unicode content round-trip should match");
    }

    @Test
    public void testEncryptDecryptFileWithSpacesAndSpecialChars() throws IOException {
        String specialFileName = "my file (special) @#$%.txt";
        Path inputFile = tempDir.resolve(specialFileName);
        String content = "Content with special chars in path";
        Files.writeString(inputFile, content, StandardCharsets.UTF_8);

        Path encryptedFile = tempDir.resolve("special chars.crbx");
        Path decryptedFile = tempDir.resolve("restored special.txt");

        processor.encryptFile(inputFile, encryptedFile, testKey);
        processor.decryptFile(encryptedFile, decryptedFile, testKey);

        String decryptedContent = Files.readString(decryptedFile, StandardCharsets.UTF_8);
        assertEquals(content, decryptedContent, "Files with special chars in path should round-trip correctly");
    }

    @Test
    public void testEncryptDecryptDirectory() throws IOException {
        // Create test directory structure
        Path sourceDir = tempDir.resolve("source");
        Path outDir = tempDir.resolve("encrypted");
        Path restoreDir = tempDir.resolve("restored");

        Files.createDirectories(sourceDir);
        Files.createDirectories(sourceDir.resolve("sub"));

        Files.writeString(sourceDir.resolve("a.txt"), "File A content", StandardCharsets.UTF_8);
        Files.writeString(sourceDir.resolve("b.txt"), "File B content", StandardCharsets.UTF_8);
        Files.writeString(sourceDir.resolve("sub").resolve("c.txt"), "File C in subdir", StandardCharsets.UTF_8);

        // Encrypt directory recursively
        processor.encryptDirectory(sourceDir, outDir, testKey, null);

        assertTrue(Files.exists(outDir.resolve("a.txt.crbx")), "a.txt.crbx should exist");
        assertTrue(Files.exists(outDir.resolve("b.txt.crbx")), "b.txt.crbx should exist");
        assertTrue(Files.exists(outDir.resolve("sub").resolve("c.txt.crbx")), "sub/c.txt.crbx should exist");

        // Decrypt directory
        processor.decryptDirectory(outDir, restoreDir, testKey);

        // Verify restored content
        assertEquals("File A content", Files.readString(restoreDir.resolve("a.txt"), StandardCharsets.UTF_8));
        assertEquals("File B content", Files.readString(restoreDir.resolve("b.txt"), StandardCharsets.UTF_8));
        assertEquals("File C in subdir", Files.readString(restoreDir.resolve("sub").resolve("c.txt"), StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptDirectoryWithExclude() throws IOException {
        Path sourceDir = tempDir.resolve("source_exclude");
        Path outDir = tempDir.resolve("encrypted_exclude");

        Files.createDirectories(sourceDir);
        Files.writeString(sourceDir.resolve("keep.txt"), "Keep me", StandardCharsets.UTF_8);
        Files.writeString(sourceDir.resolve("skip.log"), "Skip me", StandardCharsets.UTF_8);
        Files.writeString(sourceDir.resolve(".git"), "Not a real git", StandardCharsets.UTF_8);

        // Exclude .log and .git files
        processor.encryptDirectory(sourceDir, outDir, testKey, ".git,*.log");

        assertTrue(Files.exists(outDir.resolve("keep.txt.crbx")), "keep.txt should be encrypted");
        assertFalse(Files.exists(outDir.resolve("skip.log.crbx")), "skip.log should be excluded");
        assertFalse(Files.exists(outDir.resolve(".git.crbx")), ".git should be excluded");
    }

    @Test
    public void testEncryptNonExistentFile() {
        Path nonExistent = tempDir.resolve("nonexistent.txt");
        Path output = tempDir.resolve("output.crbx");

        assertThrows(Errors.FileOperationException.class, () -> {
            processor.encryptFile(nonExistent, output, testKey);
        }, "Encrypting non-existent file should throw FileOperationException");
    }

    @Test
    public void testDecryptNonExistentFile() {
        Path nonExistent = tempDir.resolve("nonexistent.crbx");
        Path output = tempDir.resolve("output.txt");

        assertThrows(Errors.FileOperationException.class, () -> {
            processor.decryptFile(nonExistent, output, testKey);
        }, "Decrypting non-existent file should throw FileOperationException");
    }

    @Test
    public void testEncryptDecryptBinaryData() throws IOException {
        Path inputFile = tempDir.resolve("binary.bin");
        byte[] binaryData = new byte[256];
        for (int i = 0; i < 256; i++) {
            binaryData[i] = (byte) i;
        }
        Files.write(inputFile, binaryData);

        Path encryptedFile = tempDir.resolve("binary.crbx");
        Path decryptedFile = tempDir.resolve("binary_restored.bin");

        processor.encryptFile(inputFile, encryptedFile, testKey);
        processor.decryptFile(encryptedFile, decryptedFile, testKey);

        byte[] restoredData = Files.readAllBytes(decryptedFile);
        assertArrayEquals(binaryData, restoredData, "Binary data round-trip should preserve all bytes");
    }

    @Test
    public void testEncryptDecryptWithCorruptedContainer() throws IOException {
        Path inputFile = tempDir.resolve("corrupt_source.txt");
        Files.writeString(inputFile, "Data to be corrupted", StandardCharsets.UTF_8);

        Path encryptedFile = tempDir.resolve("corrupt.crbx");
        processor.encryptFile(inputFile, encryptedFile, testKey);

        // Corrupt the encrypted file
        byte[] corruptedData = Files.readAllBytes(encryptedFile);
        corruptedData[corruptedData.length - 1] ^= 0xFF; // Flip the last byte
        Files.write(encryptedFile, corruptedData);

        Path decryptedFile = tempDir.resolve("corrupt_restored.txt");

        assertThrows(Errors.DecryptionException.class, () -> {
            processor.decryptFile(encryptedFile, decryptedFile, testKey);
        }, "Decrypting corrupted container should fail");
    }

    @Test
    public void testMultipleEncryptDecryptOperations() throws IOException {
        for (int i = 0; i < 5; i++) {
            Path inputFile = tempDir.resolve("multi_" + i + ".txt");
            String content = "Multiple operation test iteration " + i;
            Files.writeString(inputFile, content, StandardCharsets.UTF_8);

            Path encryptedFile = tempDir.resolve("multi_" + i + ".crbx");
            Path decryptedFile = tempDir.resolve("multi_" + i + "_restored.txt");

            processor.encryptFile(inputFile, encryptedFile, testKey);
            processor.decryptFile(encryptedFile, decryptedFile, testKey);

            String decryptedContent = Files.readString(decryptedFile, StandardCharsets.UTF_8);
            assertEquals(content, decryptedContent, "Multiple encrypt/decrypt should work");
        }
    }

    @Test
    public void testEncryptDecryptWithDifferentKeyPerOperation() throws IOException {
        for (int i = 0; i < 3; i++) {
            // Generate a unique key each iteration
            byte[] uniqueKey = CryptoEngine.generateKey();

            Path inputFile = tempDir.resolve("keytest_" + i + ".txt");
            String content = "Key test iteration " + i;
            Files.writeString(inputFile, content, StandardCharsets.UTF_8);

            Path encryptedFile = tempDir.resolve("keytest_" + i + ".crbx");
            Path decryptedFile = tempDir.resolve("keytest_" + i + "_restored.txt");

            processor.encryptFile(inputFile, encryptedFile, uniqueKey);
            processor.decryptFile(encryptedFile, decryptedFile, uniqueKey);

            String decryptedContent = Files.readString(decryptedFile, StandardCharsets.UTF_8);
            assertEquals(content, decryptedContent, "Different key per operation should work");

            // Clear key
            java.util.Arrays.fill(uniqueKey, (byte) 0);
        }
    }
}