package com.passwordmanager.services;

import com.passwordmanager.models.User;
import com.passwordmanager.models.VaultEntry;
import com.passwordmanager.utils.AppPaths;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseServiceTest {

    @TempDir
    static Path tempDir;

    private static DatabaseService db;

    @BeforeAll
    static void setUp() throws Exception {
        System.setProperty(AppPaths.DATA_DIR_PROPERTY, tempDir.toString());
        DatabaseService.resetForTests();
        db = DatabaseService.getInstance();
        db.initialize();
    }

    @AfterAll
    static void tearDown() {
        DatabaseService.resetForTests();
        System.clearProperty(AppPaths.DATA_DIR_PROPERTY);
    }

    @Test
    void createsAndFindsUsers() throws Exception {
        String username = "alice-" + UUID.randomUUID();
        String id = UUID.randomUUID().toString();

        db.createUser(id, username, "hash", "salt");
        assertTrue(db.hasAnyUser());

        Optional<User> found = db.findUserByUsername(username);
        assertTrue(found.isPresent());
        assertEquals(id, found.get().id());
        assertEquals(0, found.get().failedAttempts());
        assertNotNull(found.get().createdAt());

        assertEquals(username, db.findUserById(id).orElseThrow().username());
        assertTrue(db.findUserById("missing").isEmpty());
        assertTrue(db.findUserByUsername("missing-" + username).isEmpty());
    }

    @Test
    void usernamesAreUnique() throws Exception {
        String username = "bob-" + UUID.randomUUID();
        db.createUser(UUID.randomUUID().toString(), username, "hash", "salt");

        SQLException error = assertThrows(SQLException.class,
            () -> db.createUser(UUID.randomUUID().toString(), username, "hash", "salt"));
        assertTrue(error.getMessage().toLowerCase().contains("unique"));
    }

    @Test
    void storesEncryptedEntriesScopedToTheirUser() throws Exception {
        String alice = createUser("alice");
        String bob = createUser("bob");

        VaultEntry aliceEntry = entry(alice, "GitHub", "alice@example.com");
        VaultEntry bobEntry = entry(bob, "Bank", "bob@example.com");
        db.createEntry(aliceEntry);
        db.createEntry(bobEntry);

        List<VaultEntry> aliceEntries = db.getEntriesForUser(alice);
        assertEquals(1, aliceEntries.size());
        assertEquals("GitHub", aliceEntries.get(0).title());

        assertEquals(List.of("Bank"),
            db.getEntriesForUser(bob).stream().map(VaultEntry::title).toList());

        assertTrue(db.getEntry(aliceEntry.id(), bob).isEmpty(),
            "one user must never read another user's entry");
        assertEquals(aliceEntry.id(), db.getEntry(aliceEntry.id(), alice).orElseThrow().id());
    }

    @Test
    void updatesDeletesAndFavouritesEntries() throws Exception {
        String userId = createUser("carol");
        VaultEntry original = entry(userId, "Old title", "carol@example.com");
        db.createEntry(original);

        db.updateEntry(original.id(), userId, "New title", "new@example.com",
            "https://new.example", "Card", true, "iv2", "cipher2", null, null);

        VaultEntry updated = db.getEntry(original.id(), userId).orElseThrow();
        assertEquals("New title", updated.title());
        assertEquals("new@example.com", updated.entryUsername());
        assertEquals("Card", updated.category());
        assertTrue(updated.isFavorite());
        assertEquals("iv2", updated.passwordIv());
        assertFalse(updated.updatedAt().isBefore(updated.createdAt()));

        db.toggleFavorite(original.id(), userId, false);
        assertFalse(db.getEntry(original.id(), userId).orElseThrow().isFavorite());

        db.deleteEntry(original.id(), userId);
        assertTrue(db.getEntry(original.id(), userId).isEmpty());
    }

    @Test
    void tracksLockoutStateAndResetsIt() throws Exception {
        String userId = createUser("dave");

        db.incrementFailedAttempts(userId);
        db.incrementFailedAttempts(userId);
        LocalDateTime until = LocalDateTime.now().plusMinutes(30);
        db.lockUser(userId, until);

        User locked = db.findUserById(userId).orElseThrow();
        assertEquals(2, locked.failedAttempts());
        assertNotNull(locked.lockedUntil());

        db.resetFailedAttempts(userId);
        User reset = db.findUserById(userId).orElseThrow();
        assertEquals(0, reset.failedAttempts());
        assertEquals(null, reset.lockedUntil());
    }

    @Test
    void databaseFilesAreOwnerOnly() throws Exception {
        Assumptions.assumeTrue(
            FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));

        Path dbFile = AppPaths.getDatabasePath();
        Path dir = dbFile.getParent();

        assertEquals("rw-------",
            PosixFilePermissions.toString(Files.getPosixFilePermissions(dbFile)));
        assertEquals("rwx------",
            PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
    }

    @Test
    void initializeIsIdempotent() throws Exception {
        db.initialize();
        assertTrue(db.hasAnyUser());
    }

    // ─── helpers ──────────────────────────────────────────────────────────────

    private static String createUser(String label) throws SQLException {
        String username = label + "-" + UUID.randomUUID();
        String id = UUID.randomUUID().toString();
        db.createUser(id, username, "hash", "salt");
        return id;
    }

    private static VaultEntry entry(String userId, String title, String username) {
        LocalDateTime now = LocalDateTime.now();
        return new VaultEntry(
            UUID.randomUUID().toString(), userId, title, username,
            "https://example.com", "Login", false,
            "iv", "cipher", null, null, now, now);
    }
}
