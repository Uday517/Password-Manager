package com.passwordmanager.services;

import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.GeneratorOptions;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.StringLength;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Property-based tests: instead of a handful of examples they check the
 * invariants over hundreds of generated inputs.
 */
class CryptoPropertyTest {

    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    private final CryptoService crypto = CryptoService.getInstance();

    @Property(tries = 300)
    void encryptionRoundTripsForArbitraryText(@ForAll @StringLength(max = 300) String plaintext)
            throws Exception {
        byte[] key = randomKey();
        try {
            EncryptedData encrypted = crypto.encrypt(plaintext, key);
            assertEquals(plaintext, crypto.decrypt(encrypted, key));
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    @Property(tries = 300)
    void generatedPasswordsRespectEveryOption(
            @ForAll @IntRange(min = 4, max = 128) int length,
            @ForAll boolean upper,
            @ForAll boolean lower,
            @ForAll boolean digits,
            @ForAll boolean special) {

        GeneratorOptions opts = new GeneratorOptions(length, upper, lower, digits, special);
        String password = crypto.generatePassword(opts);

        assertEquals(length, password.length());

        boolean anySelected = upper || lower || digits || special;
        StringBuilder alphabet = new StringBuilder();
        if (upper) alphabet.append(UPPER);
        if (lower) alphabet.append(LOWER);
        if (digits) alphabet.append(DIGITS);
        if (special) alphabet.append(SPECIAL);
        if (!anySelected) alphabet.append(LOWER);

        String allowed = alphabet.toString();
        for (int i = 0; i < password.length(); i++) {
            assertTrue(allowed.indexOf(password.charAt(i)) >= 0,
                () -> "unexpected character in generated password: " + password);
        }

        if (upper) assertTrue(containsAny(password, UPPER));
        if (lower) assertTrue(containsAny(password, LOWER));
        if (digits) assertTrue(containsAny(password, DIGITS));
        if (special) assertTrue(containsAny(password, SPECIAL));
    }

    private static boolean containsAny(String password, String set) {
        for (int i = 0; i < password.length(); i++) {
            if (set.indexOf(password.charAt(i)) >= 0) return true;
        }
        return false;
    }

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }
}
