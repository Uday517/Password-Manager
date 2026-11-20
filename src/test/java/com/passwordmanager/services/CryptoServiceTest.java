package com.passwordmanager.services;

import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.GeneratorOptions;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoServiceTest {

    private final CryptoService crypto = CryptoService.getInstance();
    private final char[] masterPassword = "Correct-Horse-Battery-Staple-9!".toCharArray();

    @Test
    void masterPasswordHashUsesFreshSaltAndVerifies() throws Exception {
        String[] first = crypto.hashMasterPassword(masterPassword);
        String[] second = crypto.hashMasterPassword(masterPassword);

        assertNotEquals(first[0], second[0], "each registration needs a fresh salt");
        assertTrue(crypto.verifyMasterPassword(masterPassword, first[0], first[1]));
        assertFalse(crypto.verifyMasterPassword(
            "wrong-password".toCharArray(), first[0], first[1]));
    }

    @Test
    void rejectsMalformedStoredCredentials() {
        assertThrows(IllegalArgumentException.class,
            () -> crypto.verifyMasterPassword(masterPassword, "not-base64!!", "abc"));
        assertThrows(IllegalArgumentException.class,
            () -> crypto.verifyMasterPassword(masterPassword, "", ""));
        assertThrows(IllegalArgumentException.class,
            () -> crypto.hashMasterPassword(new char[0]));
    }

    @Test
    void vaultKeyIsDeterministicAndDomainSeparatedFromAuthHash() throws Exception {
        String[] stored = crypto.hashMasterPassword(masterPassword);
        byte[] key1 = crypto.deriveVaultKey(masterPassword, stored[0]);
        byte[] key2 = crypto.deriveVaultKey(masterPassword, stored[0]);

        assertArrayEquals(key1, key2);
        assertEquals(32, key1.length);
        assertFalse(Arrays.equals(key1, Base64.getDecoder().decode(stored[1])),
            "vault key must not equal the stored auth hash");
    }

    @Test
    void encryptsAndDecryptsUnicode() throws Exception {
        byte[] key = crypto.deriveVaultKey(masterPassword,
            crypto.hashMasterPassword(masterPassword)[0]);

        String[] samples = {
            "simple-password",
            "pässwörd-€uro-🔐",
            "line1\nline2\ttab",
            "",
            "x".repeat(10_000)
        };
        for (String sample : samples) {
            EncryptedData encrypted = crypto.encrypt(sample, key);
            assertEquals(sample, crypto.decrypt(encrypted, key));
        }
        Arrays.fill(key, (byte) 0);
    }

    @Test
    void encryptsWithFreshIvEveryTime() throws Exception {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);

        EncryptedData first = crypto.encrypt("same plaintext", key);
        EncryptedData second = crypto.encrypt("same plaintext", key);

        assertNotEquals(first.iv(), second.iv());
        assertNotEquals(first.ciphertext(), second.ciphertext());
        assertEquals(12, Base64.getDecoder().decode(first.iv()).length);
    }

    @Test
    void detectsTamperedCiphertext() throws Exception {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 3);

        EncryptedData encrypted = crypto.encrypt("do not modify", key);
        byte[] raw = Base64.getDecoder().decode(encrypted.ciphertext());
        raw[raw.length - 1] ^= 0x01;
        EncryptedData tampered = new EncryptedData(
            encrypted.iv(), Base64.getEncoder().encodeToString(raw));

        assertThrows(AEADBadTagException.class, () -> crypto.decrypt(tampered, key));
    }

    @Test
    void rejectsWrongKeyAndMalformedCiphertext() throws Exception {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 1);
        byte[] wrongKey = new byte[32];
        Arrays.fill(wrongKey, (byte) 2);

        EncryptedData encrypted = crypto.encrypt("secret", key);
        assertThrows(AEADBadTagException.class, () -> crypto.decrypt(encrypted, wrongKey));

        String badIv = Base64.getEncoder().encodeToString(new byte[8]);
        assertThrows(IllegalArgumentException.class,
            () -> crypto.decrypt(new EncryptedData(badIv, encrypted.ciphertext()), key));

        String tinyCipher = Base64.getEncoder().encodeToString(new byte[4]);
        assertThrows(IllegalArgumentException.class,
            () -> crypto.decrypt(new EncryptedData(encrypted.iv(), tinyCipher), key));

        assertThrows(IllegalArgumentException.class,
            () -> crypto.encrypt("x", new byte[16]));
    }

    @Test
    void generatedPasswordContainsEverySelectedClass() {
        GeneratorOptions all = new GeneratorOptions(32, true, true, true, true);
        for (int i = 0; i < 100; i++) {
            String password = crypto.generatePassword(all);
            assertEquals(32, password.length());
            assertTrue(password.chars().anyMatch(Character::isUpperCase));
            assertTrue(password.chars().anyMatch(Character::isLowerCase));
            assertTrue(password.chars().anyMatch(Character::isDigit));
            assertTrue(password.chars().anyMatch(c -> !Character.isLetterOrDigit(c)));
        }
    }

    @Test
    void generatedPasswordHonoursNarrowAlphabets() {
        GeneratorOptions digitsOnly = new GeneratorOptions(20, false, false, true, false);
        for (int i = 0; i < 50; i++) {
            assertTrue(crypto.generatePassword(digitsOnly).matches("[0-9]+"));
        }

        // No class selected falls back to lowercase rather than failing open.
        GeneratorOptions none = new GeneratorOptions(20, false, false, false, false);
        assertTrue(crypto.generatePassword(none).matches("[a-z]+"));

        assertThrows(IllegalArgumentException.class,
            () -> crypto.generatePassword(new GeneratorOptions(2, true, true, true, true)));
        assertThrows(IllegalArgumentException.class,
            () -> crypto.generatePassword(new GeneratorOptions(0, true, true, true, true)));
    }

    @Test
    void strengthHeuristicFlagsWeakAndRewardsLength() {
        assertEquals(0, crypto.passwordStrength("abc"));
        assertEquals(1, crypto.passwordStrength("password123"));
        assertTrue(crypto.passwordStrength("Correct-Horse-Battery-Staple-9!")
            >= crypto.passwordStrength("Abcdef12"));
        assertEquals(1, crypto.passwordStrength("aaaaaaaaaaaaaaaaaaaa"));
    }

    @Test
    void simulatedPasswordCheckIsSafeToCall() {
        crypto.simulatePasswordCheck(masterPassword);
        crypto.simulatePasswordCheck(new char[0]);
        crypto.simulatePasswordCheck(null);
    }
}
