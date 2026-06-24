package com.cryptobox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ContainerParser and Cryptobox Container v1 format validation.
 */
public class ContainerTest {

    private static final byte[] FIXED_KEY = {
        (byte) 0xb6, (byte) 0x5a, 0x38, (byte) 0x95, (byte) 0x82, (byte) 0xb7, (byte) 0xf3, (byte) 0xfd,
        0x07, (byte) 0xae, 0x22, 0x3a, 0x0f, (byte) 0xfd, 0x49, (byte) 0xd6,
        0x11, 0x40, (byte) 0xc6, (byte) 0xb5, 0x29, 0x0f, 0x79, (byte) 0x8b,
        (byte) 0xfb, 0x3e, (byte) 0xb7, (byte) 0xdd, 0x76, (byte) 0xc9, (byte) 0xfd, 0x12
    };

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Build container and parse it back successfully")
    void testBuildAndParse() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        byte[] plaintext = "Test data for container round-trip".getBytes();
        sr.nextBytes(salt);
        sr.nextBytes(iv);

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] kdfId = {0x00, 0x01};

        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        assertNotNull(container);
        assertTrue(container.length > 50);

        ContainerParser.ContainerData parsed = ContainerParser.parse(container);
        assertNotNull(parsed);
        assertArrayEquals(Config.MAGIC, parsed.magic);
        assertArrayEquals(Config.VERSION_BYTES, parsed.version);
        assertArrayEquals(salt, parsed.salt);
        assertArrayEquals(iv, parsed.iv);
        assertArrayEquals(ciphertext, parsed.ciphertext);
    }

    @Test
    @DisplayName("Parse valid sample container from testdata")
    void testParseSampleContainer() throws Exception {
        Path samplePath = Path.of("testdata/valid_containers/sample.crbx");
        assertTrue(Files.exists(samplePath), "Sample container file must exist");

        byte[] containerData = Files.readAllBytes(samplePath);
        ContainerParser.ContainerData parsed = ContainerParser.parse(containerData);

        assertArrayEquals(Config.MAGIC, parsed.magic);
        assertArrayEquals(Config.VERSION_BYTES, parsed.version);
        assertEquals(16, parsed.salt.length);
        assertEquals(12, parsed.iv.length);
        assertTrue(parsed.ciphertext.length > 16);
    }

    @Test
    @DisplayName("Parse invalid container: bad magic bytes")
    void testBadMagic() throws Exception {
        Path badMagicPath = Path.of("testdata/invalid_containers/bad_magic.crbx");
        assertTrue(Files.exists(badMagicPath));

        byte[] containerData = Files.readAllBytes(badMagicPath);
        assertThrows(Errors.ContainerFormatException.class,
            () -> ContainerParser.parse(containerData),
            "Should reject container with invalid magic");
    }

    @Test
    @DisplayName("Parse invalid container: truncated data")
    void testTruncated() throws Exception {
        Path truncatedPath = Path.of("testdata/invalid_containers/truncated.crbx");
        assertTrue(Files.exists(truncatedPath));

        byte[] containerData = Files.readAllBytes(truncatedPath);
        assertThrows(Errors.ContainerFormatException.class,
            () -> ContainerParser.parse(containerData),
            "Should reject truncated container");
    }

    @Test
    @DisplayName("Parse invalid container: corrupted GCM tag")
    void testBadTag(@TempDir Path tempDir) throws Exception {
        Path badTagPath = Path.of("testdata/invalid_containers/bad_tag.crbx");
        assertTrue(Files.exists(badTagPath));

        byte[] containerData = Files.readAllBytes(badTagPath);
        ContainerParser.ContainerData parsed = ContainerParser.parse(containerData);
        // parse should succeed (format is valid), but decryption must fail
        assertNotNull(parsed);

        assertThrows(Errors.DecryptionException.class,
            () -> CryptoEngine.decrypt(parsed.ciphertext, FIXED_KEY, parsed.iv),
            "Decryption of corrupted container must fail");
    }

    @Test
    @DisplayName("Parse null or empty data")
    void testNullAndEmpty() {
        assertThrows(Errors.ContainerFormatException.class,
            () -> ContainerParser.parse(null),
            "Null data should throw exception");

        assertThrows(Errors.ContainerFormatException.class,
            () -> ContainerParser.parse(new byte[0]),
            "Empty data should throw exception");
    }

    @Test
    @DisplayName("Build container with different KDF IDs")
    void testBuildWithDifferentKdfIds() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        byte[] plaintext = "KDF test".getBytes();
        sr.nextBytes(salt);
        sr.nextBytes(iv);

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);

        // Test with Argon2id KDF ID
        byte[] kdfArgon2 = {0x00, 0x01};
        byte[] container1 = ContainerParser.build(kdfArgon2, salt, iv, ciphertext);
        ContainerParser.ContainerData parsed1 = ContainerParser.parse(container1);
        assertArrayEquals(kdfArgon2, parsed1.kdfId);

        // Test with PBKDF2 KDF ID
        byte[] kdfPbkdf2 = {0x00, 0x02};
        byte[] container2 = ContainerParser.build(kdfPbkdf2, salt, iv, ciphertext);
        ContainerParser.ContainerData parsed2 = ContainerParser.parse(container2);
        assertArrayEquals(kdfPbkdf2, parsed2.kdfId);
    }

    @Test
    @DisplayName("Build container with empty plaintext (just GCM tag)")
    void testEmptyPlaintext() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        byte[] plaintext = new byte[0];
        sr.nextBytes(salt);
        sr.nextBytes(iv);

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] kdfId = {0x00, 0x01};

        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        ContainerParser.ContainerData parsed = ContainerParser.parse(container);

        byte[] decrypted = CryptoEngine.decrypt(parsed.ciphertext, FIXED_KEY, parsed.iv);
        assertEquals(0, decrypted.length);
    }

    @Test
    @DisplayName("Container integrity: parse-build-parse round trip")
    void testContainerIntegrityRoundTrip() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        sr.nextBytes(salt);
        sr.nextBytes(iv);

        String original = "Round-trip integrity test for container format. " +
                         "The container should survive build/parse cycles unchanged.";
        byte[] plaintext = original.getBytes();
        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] kdfId = {0x00, 0x01};

        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        ContainerParser.ContainerData parsed = ContainerParser.parse(container);

        byte[] rebuiltContainer = ContainerParser.build(parsed.kdfId, parsed.salt, parsed.iv, parsed.ciphertext);
        assertArrayEquals(container, rebuiltContainer, "Re-built container must match original");

        byte[] decrypted = CryptoEngine.decrypt(parsed.ciphertext, FIXED_KEY, parsed.iv);
        assertEquals(original, new String(decrypted));
    }

    @Test
    @DisplayName("Container with wrong key must fail decryption")
    void testWrongKeyDecryption() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        byte[] plaintext = "Secret message".getBytes();
        sr.nextBytes(salt);
        sr.nextBytes(iv);

        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] kdfId = {0x00, 0x01};
        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);

        ContainerParser.ContainerData parsed = ContainerParser.parse(container);

        // Different key
        byte[] wrongKey = new byte[32];
        sr.nextBytes(wrongKey);

        assertThrows(Errors.DecryptionException.class,
            () -> CryptoEngine.decrypt(parsed.ciphertext, wrongKey, parsed.iv),
            "Wrong key must cause decryption failure");
    }

    @Test
    @DisplayName("Container with unsupported version must be rejected")
    void testUnsupportedVersion() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        sr.nextBytes(salt);
        sr.nextBytes(iv);

        byte[] plaintext = "Version test".getBytes();
        byte[] ciphertext = CryptoEngine.encrypt(plaintext, FIXED_KEY, iv);
        byte[] kdfId = {0x00, 0x01};

        byte[] container = ContainerParser.build(kdfId, salt, iv, ciphertext);
        // Corrupt version bytes
        container[4] = 0x00;
        container[5] = 0x02; // unsupported version

        assertThrows(Errors.ContainerFormatException.class,
            () -> ContainerParser.parse(container),
            "Unsupported version must be rejected");
    }
}