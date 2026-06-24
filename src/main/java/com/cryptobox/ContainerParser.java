package com.cryptobox;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Parses and generates the Cryptobox container format.
 * <p>
 * Container structure:
 * <pre>
 * Magic:       4 bytes "CRBX"
 * Version:     2 bytes (0x0001)
 * Algorithm:   2 bytes (0x01 = AES-256-GCM)
 * KDF ID:      2 bytes (0x01 = Argon2id, 0x02 = PBKDF2)
 * Salt length: 2 bytes (uint16 big-endian)
 * Salt:        <Salt length> bytes
 * IV length:   2 bytes (uint16 big-endian)
 * IV:          <IV length> bytes
 * Ciphertext:  4 bytes (uint32 big-endian) length + ciphertext + 16-byte GCM tag
 * </pre>
 * </p>
 */
public final class ContainerParser {

    private ContainerParser() {
        // Utility class
    }

    /**
     * Result of parsing a Cryptobox container.
     */
    public static class ContainerData {
        public final byte[] magic;
        public final byte[] version;
        public final byte[] algorithmId;
        public final byte[] kdfId;
        public final byte[] salt;
        public final byte[] iv;
        public final byte[] ciphertext;

        public ContainerData(byte[] magic, byte[] version, byte[] algorithmId,
                             byte[] kdfId, byte[] salt, byte[] iv, byte[] ciphertext) {
            this.magic = magic;
            this.version = version;
            this.algorithmId = algorithmId;
            this.kdfId = kdfId;
            this.salt = salt;
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    /**
     * Parses and validates a Cryptobox container from raw bytes.
     *
     * @param data the raw container bytes
     * @return parsed container data
     * @throws Errors.ContainerFormatException if validation fails
     */
    public static ContainerData parse(byte[] data) {
        if (data == null || data.length < 10) {
            throw new Errors.ContainerFormatException("Data too short for Cryptobox container");
        }

        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        int pos = 0;

        // Magic
        byte[] magic = new byte[Config.MAGIC_LENGTH];
        buf.get(magic);
        pos += Config.MAGIC_LENGTH;

        if (!Arrays.equals(magic, Config.MAGIC)) {
            throw new Errors.ContainerFormatException("Invalid magic bytes: not a Cryptobox container");
        }

        // Version
        byte[] version = new byte[Config.VERSION_LENGTH];
        buf.get(version);
        pos += Config.VERSION_LENGTH;

        if (!Arrays.equals(version, Config.VERSION_BYTES)) {
            throw new Errors.ContainerFormatException("Unsupported container version");
        }

        // Algorithm
        byte[] algorithmId = new byte[Config.ALGORITHM_ID_LENGTH];
        buf.get(algorithmId);
        pos += Config.ALGORITHM_ID_LENGTH;

        // KDF
        byte[] kdfId = new byte[Config.KDF_ID_LENGTH];
        buf.get(kdfId);
        pos += Config.KDF_ID_LENGTH;

        // Salt length
        int saltLen = buf.getShort() & 0xFFFF;
        pos += Config.SALT_LENGTH_FIELD_SIZE;

        if (saltLen <= 0 || saltLen > 64) {
            throw new Errors.ContainerFormatException("Invalid salt length: " + saltLen);
        }
        if (pos + saltLen > data.length) {
            throw new Errors.ContainerFormatException("Container truncated: salt data missing");
        }

        byte[] salt = new byte[saltLen];
        buf.get(salt);
        pos += saltLen;

        // IV length
        int ivLen = buf.getShort() & 0xFFFF;
        pos += Config.IV_LENGTH_FIELD_SIZE;

        if (ivLen <= 0 || ivLen > 32) {
            throw new Errors.ContainerFormatException("Invalid IV length: " + ivLen);
        }
        if (pos + ivLen > data.length) {
            throw new Errors.ContainerFormatException("Container truncated: IV data missing");
        }

        byte[] iv = new byte[ivLen];
        buf.get(iv);
        pos += ivLen;

        // Ciphertext length
        int ctLen = buf.getInt();
        pos += Config.CIPHERTEXT_LENGTH_FIELD_SIZE;

        if (ctLen < 0 || pos + ctLen > data.length) {
            throw new Errors.ContainerFormatException("Invalid ciphertext length: " + ctLen);
        }

        byte[] ciphertext = new byte[ctLen];
        buf.get(ciphertext);

        return new ContainerData(magic, version, algorithmId, kdfId, salt, iv, ciphertext);
    }

    /**
     * Builds a Cryptobox container from its components.
     *
     * @param kdfId      KDF identifier
     * @param salt       salt bytes
     * @param iv         initialization vector
     * @param ciphertext ciphertext (with GCM tag)
     * @return the complete container as a byte array
     */
    public static byte[] build(byte[] kdfId, byte[] salt, byte[] iv, byte[] ciphertext) {
        int totalSize = Config.MAGIC_LENGTH
                + Config.VERSION_LENGTH
                + Config.ALGORITHM_ID_LENGTH
                + Config.KDF_ID_LENGTH
                + Config.SALT_LENGTH_FIELD_SIZE
                + salt.length
                + Config.IV_LENGTH_FIELD_SIZE
                + iv.length
                + Config.CIPHERTEXT_LENGTH_FIELD_SIZE
                + ciphertext.length;

        ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN);

        buf.put(Config.MAGIC);
        buf.put(Config.VERSION_BYTES);
        buf.put(new byte[]{0x00, Config.ALGORITHM_AES256_GCM});
        buf.put(kdfId);
        buf.putShort((short) salt.length);
        buf.put(salt);
        buf.putShort((short) iv.length);
        buf.put(iv);
        buf.putInt(ciphertext.length);
        buf.put(ciphertext);

        return buf.array();
    }

    /**
     * Verifies the GCM authentication tag by attempting decryption.
     *
     * @param containerData the raw container bytes
     * @param key           32-byte AES key
     * @return true if tag is valid
     * @throws Errors.DecryptionException if tag verification fails
     */
    public static boolean verifyTag(byte[] containerData, byte[] key) {
        ContainerData parsed = parse(containerData);
        try {
            CryptoEngine.decrypt(parsed.ciphertext, key, parsed.iv);
            return true;
        } catch (Errors.DecryptionException e) {
            throw e;
        }
    }
}