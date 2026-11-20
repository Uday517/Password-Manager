package com.passwordmanager.services;

import com.passwordmanager.models.User;
import com.passwordmanager.utils.AppPaths;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceTest {

    @TempDir
    static Path tempDir;

    private static DatabaseService db;
    private static AuthService auth;

    private static final char[] GOOD_PASSWORD = "Correct-Horse-Battery-Staple-9!".toCharArray();

    @BeforeAll
    static void setUp() throws Exception {
        System.setProperty(AppPaths.DATA_DIR_PROPERTY, tempDir.toString());
        DatabaseService.resetForTests();
        AuthService.resetForTests();
        db = DatabaseService.getInstance();
        db.initialize();
        auth = AuthService.getInstance();
    }

    @AfterAll
    static void tearDown() {
        DatabaseService.resetForTests();
        AuthService.resetForTests();
        System.clearProperty(AppPaths.DATA_DIR_PROPERTY);
    }

    @Test
    void registersAndAuthenticates() throws Exception {
        String username = "user-" + UUID.randomUUID();
        User user = auth.register(username, GOOD_PASSWORD);

        assertNotNull(user.id());
        assertEquals(username, user.username());
        assertNotEquals(new String(GOOD_PASSWORD), user.passwordHash());
        assertEquals(32, java.util.Base64.getDecoder().decode(user.passwordSalt()).length);

        AuthService.LoginResult result = auth.authenticate(username, GOOD_PASSWORD);
        assertEquals(AuthService.Status.SUCCESS, result.status());
        assertEquals(user.id(), result.user().id());
    }

    @Test
    void rejectsInvalidRegistrationInput() {
        assertThrows(AuthService.AuthException.class,
            () -> auth.register("", GOOD_PASSWORD));
        assertThrows(AuthService.AuthException.class,
            () -> auth.register("a", GOOD_PASSWORD));
        assertThrows(AuthService.AuthException.class,
            () -> auth.register("bad name", GOOD_PASSWORD));
        assertThrows(AuthService.AuthException.class,
            () -> auth.register("valid-name", "short".toCharArray()));
        assertThrows(AuthService.AuthException.class,
            () -> auth.register("valid-name", "password123".toCharArray()));
    }

    @Test
    void rejectsDuplicateUsernames() throws Exception {
        String username = "duplicate-" + UUID.randomUUID();
        auth.register(username, GOOD_PASSWORD);

        AuthService.AuthException error = assertThrows(AuthService.AuthException.class,
            () -> auth.register(username, GOOD_PASSWORD));
        assertTrue(error.getMessage().toLowerCase().contains("already taken"));
    }

    @Test
    void locksAfterFiveFailuresAndRejectsCorrectPasswordWhileLocked() throws Exception {
        String username = "locked-" + UUID.randomUUID();
        auth.register(username, GOOD_PASSWORD);

        for (int attempt = 1; attempt <= 4; attempt++) {
            AuthService.LoginResult result = auth.authenticate(username, "wrong".toCharArray());
            assertEquals(AuthService.Status.INVALID_CREDENTIALS, result.status());
            assertEquals(5 - attempt, result.remainingAttempts());
        }

        AuthService.LoginResult fifth = auth.authenticate(username, "wrong".toCharArray());
        assertEquals(AuthService.Status.LOCKED, fifth.status());
        assertEquals(AuthService.LOCKOUT_MINUTES, fifth.lockoutMinutes());

        AuthService.LoginResult correctWhileLocked =
            auth.authenticate(username, GOOD_PASSWORD);
        assertEquals(AuthService.Status.LOCKED, correctWhileLocked.status());

        User stored = db.findUserByUsername(username).orElseThrow();
        assertEquals(5, stored.failedAttempts());
        assertNotNull(stored.lockedUntil());
    }

    @Test
    void expiredLockoutResetsTheCounter() throws Exception {
        String username = "expired-" + UUID.randomUUID();
        User user = auth.register(username, GOOD_PASSWORD);

        db.incrementFailedAttempts(user.id());
        db.lockUser(user.id(), LocalDateTime.now().minusMinutes(1));

        AuthService.LoginResult result = auth.authenticate(username, GOOD_PASSWORD);
        assertEquals(AuthService.Status.SUCCESS, result.status());

        User stored = db.findUserById(user.id()).orElseThrow();
        assertEquals(0, stored.failedAttempts());
        assertNull(stored.lockedUntil());
    }

    @Test
    void successfulLoginClearsEarlierFailures() throws Exception {
        String username = "reset-" + UUID.randomUUID();
        User user = auth.register(username, GOOD_PASSWORD);

        auth.authenticate(username, "wrong".toCharArray());
        auth.authenticate(username, "wrong".toCharArray());
        assertEquals(2, db.findUserById(user.id()).orElseThrow().failedAttempts());

        assertEquals(AuthService.Status.SUCCESS,
            auth.authenticate(username, GOOD_PASSWORD).status());
        assertEquals(0, db.findUserById(user.id()).orElseThrow().failedAttempts());
    }

    @Test
    void unknownUserFailsWithoutLeakingExistence() throws Exception {
        AuthService.LoginResult result =
            auth.authenticate("missing-" + UUID.randomUUID(), GOOD_PASSWORD);

        assertEquals(AuthService.Status.INVALID_CREDENTIALS, result.status());
        assertEquals(-1, result.remainingAttempts());
    }
}
