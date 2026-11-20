package com.passwordmanager.services;

import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.GeneratorOptions;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * All cryptographic operations for the password manager.
 *
 * Security design:
 * - Master password: PBKDF2-SHA512 with 600,000 iterations + random 32-byte salt
 * - Vault key: derived from the master password via a second PBKDF2 pass with a
 *   domain-separated salt, so the stored auth hash can never double as a key
 * - Entry encryption: AES-256-GCM with a fresh random 12-byte IV per operation
 * - Password generation: SecureRandom, with every selected character class
 *   guaranteed to appear at least once
 * - Timing-safe comparison: MessageDigest.isEqual for hash verification
 *
 * NOTHING in this class touches the database or filesystem.
 */
public class CryptoService {

    private static CryptoService instance;

    // PBKDF2 parameters (NIST SP 800-132 recommendation)
    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA512";
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int HASH_LENGTH_BYTES = 32;   // 256-bit hash
    private static final int VAULT_KEY_BYTES = 32;     // 256-bit AES key
    private static final int SALT_LENGTH_BYTES = 32;   // 256-bit salt

    // AES-GCM parameters
    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;     // 96-bit IV (recommended for GCM)
    private static final int GCM_TAG_BITS = 128;       // 128-bit authentication tag
    private static final int GCM_TAG_BYTES = GCM_TAG_BITS / 8;

    // Domain separation info for vault key derivation (keeps auth key != encryption key)
    private static final byte[] VAULT_KEY_INFO =
        "vault-encryption-key-v1".getBytes(StandardCharsets.UTF_8);

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS    = "0123456789";
    private static final String SPECIAL   = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    private static final int MIN_GENERATED_LENGTH = 4;
    private static final int MAX_GENERATED_LENGTH = 256;

    private static final String[] COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "letmein", "admin",
        "welcome", "iloveyou", "monkey", "dragon", "master", "abc123"
    };

    private final SecureRandom secureRandom = new SecureRandom();

    /** Salt used by {@link #simulatePasswordCheck(char[])} to equalize login timing. */
    private final byte[] dummySalt = new byte[SALT_LENGTH_BYTES];

    private CryptoService() {
        secureRandom.nextBytes(dummySalt);
    }

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
     * @param password the master password as char[] (the caller keeps ownership)
     * @return [0] = base64 salt, [1] = base64 hash
     */
    public String[] hashMasterPassword(char[] password) throws GeneralSecurityException {
        requireNonEmpty(password);
        byte[] salt = generateSalt();
        byte[] hash = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
        try {
            return new String[]{
                Base64.getEncoder().encodeToString(salt),
                Base64.getEncoder().encodeToString(hash)
            };
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * Verify a master password against its stored salt and hash.
     * Uses timing-safe comparison to prevent timing attacks.
     */
    public boolean verifyMasterPassword(char[] password, String storedSaltB64,
                                        String storedHashB64) throws GeneralSecurityException {
        requireNonEmpty(password);
        byte[] salt = decodeBase64(storedSaltB64, "salt");
        byte[] stored = decodeBase64(storedHashB64, "hash");
        if (salt.length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Stored salt has an unexpected length");
        }
        if (stored.length != HASH_LENGTH_BYTES) {
            throw new IllegalArgumentException("Stored hash has an unexpected length");
        }

        byte[] candidate = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
        try {
            return MessageDigest.isEqual(candidate, stored);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    /**
     * Burn roughly the same CPU time as a real verification. The login screen
     * calls this when the username does not exist so that a local attacker
     * cannot enumerate usernames by measuring response time.
     */
    public void simulatePasswordCheck(char[] password) {
        if (password == null) return;
        try {
            byte[] digest = pbkdf2(password, dummySalt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
            Arrays.fill(digest, (byte) 0);
        } catch (GeneralSecurityException e) {
            // This path only exists to equalize timing; failing it is harmless.
        }
    }

    // ─── Vault Key Derivation ─────────────────────────────────────────────────

    /**
     * Derive the 256-bit vault encryption key from the master password.
     *
     * Uses a second PBKDF2 pass with a domain-separated salt
     * (storedSalt || VAULT_KEY_INFO) so the auth hash and the encryption key are
     * always different even for the same password.
     *
     * @param password master password as char[]
     * @param storedSaltB64 the base64 salt from the users table
     * @return 32-byte AES key (caller is responsible for zeroing it after use)
     */
    public byte[] deriveVaultKey(char[] password, String storedSaltB64)
            throws GeneralSecurityException {
        requireNonEmpty(password);
        byte[] salt = decodeBase64(storedSaltB64, "salt");
        if (salt.length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Stored salt has an unexpected length");
        }

        // Domain-separate: salt_for_vault_key = salt || VAULT_KEY_INFO
        byte[] domainSalt = new byte[salt.length + VAULT_KEY_INFO.length];
        System.arraycopy(salt, 0, domainSalt, 0, salt.length);
        System.arraycopy(VAULT_KEY_INFO, 0, domainSalt, salt.length, VAULT_KEY_INFO.length);

        // Fewer iterations are acceptable here because breaking the vault key
        // still requires breaking the 600k-iteration auth hash first.
        try {
            return pbkdf2(password, domainSalt, 100_000, VAULT_KEY_BYTES);
        } finally {
            Arrays.fill(domainSalt, (byte) 0);
        }
    }

    // ─── AES-256-GCM Encryption ───────────────────────────────────────────────

    /**
     * Encrypt a plaintext string with AES-256-GCM.
     * Generates a fresh random IV for every call.
     */
    public EncryptedData encrypt(String plaintext, byte[] vaultKey) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext must not be null");
        }
        requireKey(vaultKey);

        byte[] iv = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(vaultKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));

        // Java appends the 16-byte auth tag to the ciphertext in GCM mode
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        try {
            return new EncryptedData(
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(encrypted)
            );
        } finally {
            Arrays.fill(encrypted, (byte) 0);
        }
    }

    /**
     * Decrypt AES-256-GCM encrypted data. GCM authenticates the ciphertext
     * before releasing any plaintext.
     *
     * @throws AEADBadTagException if the key is wrong or the data was tampered with
     */
    public String decrypt(EncryptedData data, byte[] vaultKey) throws GeneralSecurityException {
        if (data == null) {
            throw new IllegalArgumentException("Encrypted data must not be null");
        }
        requireKey(vaultKey);

        byte[] iv = decodeBase64(data.iv(), "IV");
        byte[] ciphertextWithTag = decodeBase64(data.ciphertext(), "ciphertext");
        if (iv.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Ciphertext has an invalid IV length");
        }
        if (ciphertextWithTag.length < GCM_TAG_BYTES) {
            throw new IllegalArgumentException("Ciphertext is shorter than the GCM tag");
        }

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(vaultKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] decrypted = cipher.doFinal(ciphertextWithTag);
        try {
            return new String(decrypted, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(decrypted, (byte) 0);
        }
    }

    // ─── Password Generator ───────────────────────────────────────────────────

    /**
     * Generate a cryptographically secure random password.
     *
     * If at least one character class is selected, every selected class appears
     * at least once (as long as the requested length allows it), then the rest
     * of the password is filled and the whole array is shuffled.
     */
    public String generatePassword(GeneratorOptions opts) {
        if (opts == null) {
            throw new IllegalArgumentException("Generator options must not be null");
        }
        int length = opts.length();
        if (length < MIN_GENERATED_LENGTH || length > MAX_GENERATED_LENGTH) {
            throw new IllegalArgumentException("Password length must be between "
                + MIN_GENERATED_LENGTH + " and " + MAX_GENERATED_LENGTH);
        }

        StringBuilder alphabet = new StringBuilder(96);
        List<String> selectedClasses = new ArrayList<>(4);
        if (opts.useUppercase()) { alphabet.append(UPPERCASE); selectedClasses.add(UPPERCASE); }
        if (opts.useLowercase()) { alphabet.append(LOWERCASE); selectedClasses.add(LOWERCASE); }
        if (opts.useDigits())    { alphabet.append(DIGITS);    selectedClasses.add(DIGITS); }
        if (opts.useSpecial())   { alphabet.append(SPECIAL);   selectedClasses.add(SPECIAL); }
        if (alphabet.isEmpty())  { alphabet.append(LOWERCASE); selectedClasses.add(LOWERCASE); }

        if (selectedClasses.size() > length) {
            throw new IllegalArgumentException("Length is too short for the selected character classes");
        }

        String alpha = alphabet.toString();
        char[] password = new char[length];
        int index = 0;

        // One guaranteed character from each selected class.
        for (String set : selectedClasses) {
            password[index++] = randomFromSet(set);
        }
        // Fill the remainder from the combined alphabet.
        while (index < length) {
            password[index++] = alpha.charAt(secureRandom.nextInt(alpha.length()));
        }

        shuffle(password);
        String result = new String(password);
        Arrays.fill(password, '\0');
        return result;
    }

    // ─── Password Strength ────────────────────────────────────────────────────

    /** Convenience overload for callers that already have a String. */
    public int passwordStrength(String password) {
        return password == null ? 0 : passwordStrength(password.toCharArray());
    }

    /**
     * Returns a strength score 0-4:
     * 0 = Very Weak, 1 = Weak, 2 = Fair, 3 = Strong, 4 = Very Strong
     *
     * This is a heuristic for user feedback, not a strength proof. It rewards
     * length first (which matters most) and character variety second, and
     * penalizes a few very common passwords.
     */
    public int passwordStrength(char[] password) {
        if (password == null || password.length < 6) return 0;

        boolean hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        char first = password[0];
        boolean allSame = true;
        for (char c : password) {
            if (c != first) allSame = false;
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        boolean common = false;
        for (String candidate : COMMON_PASSWORDS) {
            if (startsWithIgnoreCase(password, candidate)) {
                common = true;
                break;
            }
        }

        int score = 0;
        if (password.length >= 8)  score++;
        if (password.length >= 12) score++;
        if (password.length >= 16) score++;
        int types = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0)
                  + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);
        if (types >= 3) score++;

        if (allSame || common) score = Math.min(score, 1);
        return Math.max(0, Math.min(score, 4));
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLengthBytes)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBytes * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGO);
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private char randomFromSet(String set) {
        return set.charAt(secureRandom.nextInt(set.length()));
    }

    private void shuffle(char[] array) {
        for (int i = array.length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char tmp = array[i];
            array[i] = array[j];
            array[j] = tmp;
        }
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != VAULT_KEY_BYTES) {
            throw new IllegalArgumentException("Vault key must be 32 bytes");
        }
    }

    private static void requireNonEmpty(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
    }

    private static boolean startsWithIgnoreCase(char[] value, String prefix) {
        if (value.length < prefix.length()) return false;
        for (int i = 0; i < prefix.length(); i++) {
            if (Character.toLowerCase(value[i]) != prefix.charAt(i)) return false;
        }
        return true;
    }

    private static byte[] decodeBase64(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing " + label);
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid base64 " + label, e);
        }
    }
}
