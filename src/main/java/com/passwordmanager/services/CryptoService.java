package com.passwordmanager.services;

import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.GeneratorOptions;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * All cryptographic operations for the password manager.
 *
 * Security design:
 * - Master password: PBKDF2-SHA512 with 600,000 iterations + random 32-byte salt
 * - Vault key: derived from master password via a secondary PBKDF2 pass (domain-separated)
 * - Entry encryption: AES-256-GCM with random 12-byte IV per entry
 * - Password generation: SecureRandom with rejection sampling (no modulo bias)
 * - Timing-safe comparison: MessageDigest.isEqual for hash verification
 *
 * NOTHING in this class touches the database or filesystem.
 */
public class CryptoService {

    private static CryptoService instance;

    // PBKDF2 parameters (NIST SP 800-132 recommendation as of 2023)
    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA512";
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int HASH_LENGTH_BYTES = 32;   // 256-bit hash
    private static final int VAULT_KEY_BYTES = 32;     // 256-bit AES key
    private static final int SALT_LENGTH_BYTES = 32;   // 256-bit salt

    // AES-GCM parameters
    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;     // 96-bit IV (recommended for GCM)
    private static final int GCM_TAG_BITS = 128;       // 128-bit authentication tag

    // Domain separation info for vault key derivation (keeps auth key ≠ encryption key)
    private static final byte[] VAULT_KEY_INFO = "vault-encryption-key-v1".getBytes(StandardCharsets.UTF_8);

    private final SecureRandom secureRandom = new SecureRandom();

    private CryptoService() {}

    public static synchronized CryptoService getInstance() {
        if (instance == null) {
            instance = new CryptoService();
        }
        return instance;
    }

    // ─── Master Password ──────────────────────────────────────────────────────

    /**
     * Hash a master password for storage. Generates a fresh random salt.
     *
     * @param password the master password as char[] (will NOT be cleared by this method)
     * @return [0] = base64 salt, [1] = base64 hash
     */
    public String[] hashMasterPassword(char[] password) throws Exception {
        byte[] salt = generateSalt();
        byte[] hash = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
        return new String[]{
            Base64.getEncoder().encodeToString(salt),
            Base64.getEncoder().encodeToString(hash)
        };
    }

    /**
     * Verify a master password against its stored salt and hash.
     * Uses timing-safe comparison to prevent timing attacks.
     */
    public boolean verifyMasterPassword(char[] password, String storedSaltB64, String storedHashB64)
            throws Exception {
        byte[] salt = Base64.getDecoder().decode(storedSaltB64);
        byte[] candidate = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
        byte[] stored = Base64.getDecoder().decode(storedHashB64);
        return MessageDigest.isEqual(candidate, stored);  // timing-safe
    }

    // ─── Vault Key Derivation ─────────────────────────────────────────────────

    /**
     * Derive the 256-bit vault encryption key from the master password.
     *
     * Uses a second PBKDF2 pass with domain-separated salt (storedSalt || VAULT_KEY_INFO)
     * so the auth hash and the encryption key are always different even with the same password.
     *
     * @param password master password as char[]
     * @param storedSaltB64 the base64 salt from the users table
     * @return 32-byte AES key (caller is responsible for zeroing after use)
     */
    public byte[] deriveVaultKey(char[] password, String storedSaltB64) throws Exception {
        byte[] salt = Base64.getDecoder().decode(storedSaltB64);

        // Domain-separate: salt_for_vault_key = salt || VAULT_KEY_INFO
        byte[] domainSalt = new byte[salt.length + VAULT_KEY_INFO.length];
        System.arraycopy(salt, 0, domainSalt, 0, salt.length);
        System.arraycopy(VAULT_KEY_INFO, 0, domainSalt, salt.length, VAULT_KEY_INFO.length);

        // Fewer iterations OK here because attacker already needed to crack PBKDF2 above
        byte[] key = pbkdf2(password, domainSalt, 100_000, VAULT_KEY_BYTES);
        Arrays.fill(domainSalt, (byte) 0);
        return key;
    }

    // ─── AES-256-GCM Encryption ───────────────────────────────────────────────

    /**
     * Encrypt a plaintext string with AES-256-GCM.
     * Generates a fresh random IV for every call.
     *
     * @param plaintext the string to encrypt
     * @param vaultKey  32-byte AES key
     * @return EncryptedData containing base64-encoded IV and ciphertext+tag
     */
    public EncryptedData encrypt(String plaintext, byte[] vaultKey) throws Exception {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        SecretKeySpec keySpec = new SecretKeySpec(vaultKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

        // Java appends the 16-byte auth tag to the ciphertext in GCM mode
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new EncryptedData(
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(encrypted)
        );
    }

    /**
     * Decrypt AES-256-GCM encrypted data. Authenticates the ciphertext before decryption.
     * Throws AEADBadTagException if the ciphertext has been tampered with.
     *
     * @param data     EncryptedData from encrypt()
     * @param vaultKey 32-byte AES key
     * @return decrypted plaintext string
     */
    public String decrypt(EncryptedData data, byte[] vaultKey) throws Exception {
        byte[] iv = Base64.getDecoder().decode(data.iv());
        byte[] ciphertextWithTag = Base64.getDecoder().decode(data.ciphertext());

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        SecretKeySpec keySpec = new SecretKeySpec(vaultKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

        byte[] decrypted = cipher.doFinal(ciphertextWithTag);
        String result = new String(decrypted, StandardCharsets.UTF_8);
        Arrays.fill(decrypted, (byte) 0);
        return result;
    }

    // ─── Password Generator ───────────────────────────────────────────────────

    /**
     * Generate a cryptographically secure random password.
     *
     * Uses rejection sampling to eliminate modulo bias — unlike the original
     * java.util.Random approach which produced predictable sequences.
     */
    public String generatePassword(GeneratorOptions opts) {
        StringBuilder alphabet = new StringBuilder(96);
        String uppercase  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowercase  = "abcdefghijklmnopqrstuvwxyz";
        String digits     = "0123456789";
        String special    = "!@#$%^&*()-_=+[]{}|;:,.<>?";

        if (opts.useUppercase()) alphabet.append(uppercase);
        if (opts.useLowercase()) alphabet.append(lowercase);
        if (opts.useDigits())    alphabet.append(digits);
        if (opts.useSpecial())   alphabet.append(special);
        if (alphabet.isEmpty())  alphabet.append(lowercase);

        String alpha = alphabet.toString();
        int len = alpha.length();
        // Largest multiple of len that fits in a byte — reject values >= this
        int maxUnbiased = (256 / len) * len;

        char[] password = new char[opts.length()];
        byte[] buf = new byte[1];
        int idx = 0;

        while (idx < opts.length()) {
            secureRandom.nextBytes(buf);
            int b = buf[0] & 0xFF;
            if (b < maxUnbiased) {
                password[idx++] = alpha.charAt(b % len);
            }
            // else: discard and retry — this is rejection sampling, eliminates bias
        }

        // Guarantee at least one character from each required character class
        if (opts.length() >= 4) {
            int pos = 0;
            if (opts.useUppercase() && !containsFrom(password, uppercase)) {
                password[pos++] = randomFromSet(uppercase);
            }
            if (opts.useLowercase() && !containsFrom(password, lowercase)) {
                password[pos++] = randomFromSet(lowercase);
            }
            if (opts.useDigits() && !containsFrom(password, digits)) {
                password[pos++] = randomFromSet(digits);
            }
            if (opts.useSpecial() && !containsFrom(password, special)) {
                password[pos] = randomFromSet(special);
            }
            // Shuffle to distribute the forced characters randomly
            shuffle(password);
        }

        String result = new String(password);
        Arrays.fill(password, '\0');
        return result;
    }

    // ─── Password Strength ────────────────────────────────────────────────────

    /**
     * Returns a strength score 0-4:
     * 0 = Very Weak, 1 = Weak, 2 = Fair, 3 = Strong, 4 = Very Strong
     */
    public int passwordStrength(String password) {
        if (password == null || password.length() < 6) return 0;
        int score = 0;
        if (password.length() >= 8)  score++;
        if (password.length() >= 12) score++;
        if (password.length() >= 16) score++;
        boolean hasUpper   = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLower   = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit   = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));
        int types = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);
        if (types >= 3) score++;
        return Math.min(score, 4);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLengthBytes)
            throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBytes * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGO);
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private boolean containsFrom(char[] password, String set) {
        for (char c : password) {
            if (set.indexOf(c) >= 0) return true;
        }
        return false;
    }

    private char randomFromSet(String set) {
        int maxUnbiased = (256 / set.length()) * set.length();
        byte[] buf = new byte[1];
        while (true) {
            secureRandom.nextBytes(buf);
            int b = buf[0] & 0xFF;
            if (b < maxUnbiased) return set.charAt(b % set.length());
        }
    }

    private void shuffle(char[] array) {
        for (int i = array.length - 1; i > 0; i--) {
            byte[] buf = new byte[1];
            int j;
            int maxUnbiased = (256 / (i + 1)) * (i + 1);
            do {
                secureRandom.nextBytes(buf);
                j = buf[0] & 0xFF;
            } while (j >= maxUnbiased);
            j = j % (i + 1);
            char tmp = array[i];
            array[i] = array[j];
            array[j] = tmp;
        }
    }
}
