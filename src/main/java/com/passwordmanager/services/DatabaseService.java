package com.passwordmanager.services;

import com.passwordmanager.models.EncryptedEntry;
import com.passwordmanager.models.User;
import com.passwordmanager.models.VaultEntry;
import com.passwordmanager.utils.AppPaths;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * All database operations for the password manager.
 *
 * Security design:
 * - Every query uses PreparedStatement — zero string concatenation in SQL
 * - WAL mode for crash safety
 * - Foreign keys enforced at the DB level
 * - DB file permissions set to 0600 (owner read/write only) on POSIX systems
 * - Schema versioned via schema_migrations table
 */
public class DatabaseService {

    private static final Logger LOG = Logger.getLogger(DatabaseService.class.getName());
    private static final DateTimeFormatter DT_FMT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static DatabaseService instance;

    private Connection conn;

    private DatabaseService() {}

    public static synchronized DatabaseService getInstance() {
        if (instance == null) {
            instance = new DatabaseService();
        }
        return instance;
    }

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    public void initialize() throws Exception {
        Path dbPath = AppPaths.getDatabasePath();
        Path dataDir = dbPath.getParent();
        Files.createDirectories(dataDir);

        // Lock the *directory* down to 0700 before opening the connection.
        //
        // Chmodding only the .db file left two holes: the file existed at the
        // default umask for the moment between DriverManager.getConnection()
        // creating it and the chmod landing, and WAL mode's vault.db-wal /
        // vault.db-shm sidecars were never chmodded at all. An unreadable parent
        // directory closes both, whatever SQLite creates inside it.
        setOwnerOnly(dataDir, "rwx------");

        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();
        conn = DriverManager.getConnection(url);

        // Belt and braces: the file itself, once it exists.
        if (Files.exists(dbPath)) {
            setOwnerOnly(dbPath, "rw-------");
        }

        // Performance and safety pragmas
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("PRAGMA foreign_keys=ON");
            st.execute("PRAGMA synchronous=NORMAL");
            // Overwrite deleted content with zeros instead of just marking the page
            // free. Without this, a deleted entry's ciphertext — and anything that
            // was ever stored in the clear — stays readable in the file with a hex
            // editor long after the row is gone.
            st.execute("PRAGMA secure_delete=ON");
        }

        runMigrations();
        LOG.info("Database initialized at: " + dbPath);
    }

    /** Best-effort POSIX permission tightening; a no-op on Windows. */
    private void setOwnerOnly(Path path, String perms) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms));
        } catch (UnsupportedOperationException | java.io.IOException e) {
            // Windows (no POSIX view) or a filesystem that refuses — not fatal.
            LOG.fine("Could not set permissions on " + path + ": " + e.getMessage());
        }
    }

    /** Runs {@code work} inside a transaction, rolling back on any exception. */
    public void inTransaction(SqlWork work) throws Exception {
        boolean previous = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            work.run();
            conn.commit();
        } catch (Exception e) {
            try {
                conn.rollback();
            } catch (SQLException rollbackFailure) {
                LOG.severe("Rollback failed: " + rollbackFailure.getMessage());
            }
            throw e;
        } finally {
            conn.setAutoCommit(previous);
        }
    }

    @FunctionalInterface
    public interface SqlWork {
        void run() throws Exception;
    }

    /**
     * Rebuild the database file, discarding free pages.
     *
     * {@code secure_delete} only governs pages freed after it was set, so it cannot
     * scrub residue that predates it. After the v1 to v2 migration the metadata
     * columns are NULL but their former contents are still sitting in free pages —
     * VACUUM writes a fresh file from the live rows only, which is what actually
     * removes them. Must run outside a transaction.
     */
    public void vacuum() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA wal_checkpoint(TRUNCATE)");
            st.execute("VACUUM");
        }
        LOG.info("Database vacuumed");
    }

    public void close() {
        try {
            if (conn != null && !conn.isClosed()) {
                conn.close();
            }
        } catch (SQLException e) {
            LOG.warning("Error closing database: " + e.getMessage());
        }
    }

    public boolean hasAnyUser() throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM users");
             ResultSet rs = ps.executeQuery()) {
            return rs.next() && rs.getInt(1) > 0;
        }
    }

    // ─── Users ────────────────────────────────────────────────────────────────

    public Optional<User> findUserByUsername(String username) throws SQLException {
        String sql = "SELECT id, username, password_hash, password_salt, created_at, " +
                     "failed_attempts, locked_until FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapUser(rs));
                }
            }
        }
        return Optional.empty();
    }

    public void createUser(String id, String username, String passwordHash, String passwordSalt)
            throws SQLException {
        String sql = "INSERT INTO users (id, username, password_hash, password_salt, created_at) " +
                     "VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, username);
            ps.setString(3, passwordHash);
            ps.setString(4, passwordSalt);
            ps.setString(5, now());
            ps.executeUpdate();
        }
    }

    public void incrementFailedAttempts(String userId) throws SQLException {
        String sql = "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userId);
            ps.executeUpdate();
        }
    }

    public void lockUser(String userId, LocalDateTime until) throws SQLException {
        String sql = "UPDATE users SET locked_until = ? WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, until.format(DT_FMT));
            ps.setString(2, userId);
            ps.executeUpdate();
        }
    }

    public void resetFailedAttempts(String userId) throws SQLException {
        String sql = "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userId);
            ps.executeUpdate();
        }
    }

    // ─── Vault Entries ────────────────────────────────────────────────────────

    private static final String ENTRY_COLUMNS =
        "id, user_id, is_favorite, meta_iv, meta_cipher, " +
        "password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at";

    public List<EncryptedEntry> getEntriesForUser(String userId) throws SQLException {
        String sql = "SELECT " + ENTRY_COLUMNS +
                     " FROM vault_entries WHERE user_id = ? ORDER BY updated_at DESC";
        List<EncryptedEntry> entries = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    entries.add(mapEntry(rs));
                }
            }
        }
        return entries;
    }

    public Optional<EncryptedEntry> getEntry(String entryId, String userId) throws SQLException {
        String sql = "SELECT " + ENTRY_COLUMNS +
                     " FROM vault_entries WHERE id = ? AND user_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, entryId);
            ps.setString(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapEntry(rs));
            }
        }
        return Optional.empty();
    }

    public void createEntry(EncryptedEntry entry) throws SQLException {
        String sql = "INSERT INTO vault_entries " +
                     "(id, user_id, is_favorite, meta_iv, meta_cipher, " +
                     " password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1,  entry.id());
            ps.setString(2,  entry.userId());
            ps.setInt(3,     entry.isFavorite() ? 1 : 0);
            ps.setString(4,  entry.metaIv());
            ps.setString(5,  entry.metaCipher());
            ps.setString(6,  entry.passwordIv());
            ps.setString(7,  entry.passwordCipher());
            ps.setString(8,  entry.notesIv());
            ps.setString(9,  entry.notesCipher());
            ps.setString(10, now());
            ps.setString(11, now());
            ps.executeUpdate();
        }
    }

    public void updateEntry(EncryptedEntry entry) throws SQLException {
        String sql = "UPDATE vault_entries SET is_favorite=?, meta_iv=?, meta_cipher=?, " +
                     "password_iv=?, password_cipher=?, notes_iv=?, notes_cipher=?, updated_at=? " +
                     "WHERE id=? AND user_id=?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1,    entry.isFavorite() ? 1 : 0);
            ps.setString(2, entry.metaIv());
            ps.setString(3, entry.metaCipher());
            ps.setString(4, entry.passwordIv());
            ps.setString(5, entry.passwordCipher());
            ps.setString(6, entry.notesIv());
            ps.setString(7, entry.notesCipher());
            ps.setString(8, now());
            ps.setString(9, entry.id());
            ps.setString(10, entry.userId());
            ps.executeUpdate();
        }
    }

    // ─── Legacy rows (KDF v1 / plaintext metadata) ────────────────────────────

    /** One un-migrated row: plaintext metadata plus the v1-encrypted secrets. */
    public record LegacyEntryRow(String id, String title, String entryUsername, String url,
                                 String category, String passwordIv, String passwordCipher,
                                 String notesIv, String notesCipher) {}

    /** Rows for this user that still have no encrypted metadata blob. */
    public List<LegacyEntryRow> getLegacyEntries(String userId) throws SQLException {
        String sql = "SELECT id, title, entry_username, url, category, password_iv, " +
                     "password_cipher, notes_iv, notes_cipher FROM vault_entries " +
                     "WHERE user_id = ? AND meta_cipher IS NULL";
        List<LegacyEntryRow> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.add(new LegacyEntryRow(
                        rs.getString("id"), rs.getString("title"), rs.getString("entry_username"),
                        rs.getString("url"), rs.getString("category"), rs.getString("password_iv"),
                        rs.getString("password_cipher"), rs.getString("notes_iv"),
                        rs.getString("notes_cipher")));
                }
            }
        }
        return rows;
    }

    /**
     * Write a converted row: encrypted metadata in, plaintext metadata wiped out.
     * Timestamps are deliberately left alone — a migration is not a user edit.
     */
    public void writeMigratedEntry(String entryId, String userId, String metaIv, String metaCipher,
                                   String passwordIv, String passwordCipher,
                                   String notesIv, String notesCipher) throws SQLException {
        String sql = "UPDATE vault_entries SET meta_iv=?, meta_cipher=?, password_iv=?, " +
                     "password_cipher=?, notes_iv=?, notes_cipher=?, " +
                     "title=NULL, entry_username=NULL, url=NULL, category=NULL " +
                     "WHERE id=? AND user_id=?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, metaIv);
            ps.setString(2, metaCipher);
            ps.setString(3, passwordIv);
            ps.setString(4, passwordCipher);
            ps.setString(5, notesIv);
            ps.setString(6, notesCipher);
            ps.setString(7, entryId);
            ps.setString(8, userId);
            ps.executeUpdate();
        }
    }

    public void deleteEntry(String entryId, String userId) throws SQLException {
        String sql = "DELETE FROM vault_entries WHERE id = ? AND user_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, entryId);
            ps.setString(2, userId);
            ps.executeUpdate();
        }
    }

    public void toggleFavorite(String entryId, String userId, boolean isFavorite) throws SQLException {
        String sql = "UPDATE vault_entries SET is_favorite = ? WHERE id = ? AND user_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, isFavorite ? 1 : 0);
            ps.setString(2, entryId);
            ps.setString(3, userId);
            ps.executeUpdate();
        }
    }

    // ─── Schema Migrations ────────────────────────────────────────────────────

    private void runMigrations() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version    INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """);
        }

        int current = getCurrentSchemaVersion();
        if (current < 1) applyMigration1();
        if (current < 2) applyMigration2();
    }

    private int getCurrentSchemaVersion() throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT MAX(version) FROM schema_migrations")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    private void applyMigration1() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id              TEXT PRIMARY KEY,
                    username        TEXT NOT NULL UNIQUE,
                    password_hash   TEXT NOT NULL,
                    password_salt   TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until    TEXT
                )
                """);

            st.execute("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id              TEXT PRIMARY KEY,
                    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    title           TEXT NOT NULL,
                    entry_username  TEXT,
                    url             TEXT,
                    category        TEXT NOT NULL DEFAULT 'Login',
                    is_favorite     INTEGER NOT NULL DEFAULT 0,
                    password_iv     TEXT NOT NULL,
                    password_cipher TEXT NOT NULL,
                    notes_iv        TEXT,
                    notes_cipher    TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                )
                """);

            st.execute("CREATE INDEX IF NOT EXISTS idx_entries_user ON vault_entries(user_id)");
            st.execute("CREATE INDEX IF NOT EXISTS idx_entries_category ON vault_entries(user_id, category)");
        }

        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)")) {
            ps.setString(1, now());
            ps.executeUpdate();
        }
    }

    /**
     * Schema v2 — encrypted metadata and the unified KDF.
     *
     * Adds the encrypted metadata blob columns and a per-user {@code kdf_version}.
     * The old plaintext columns (title, entry_username, url, category) are left in
     * place and nullable: rows still need them until each user logs in and their
     * vault is re-encrypted, since only then is the master password available.
     * {@link VaultMigrationService} clears them per user as it converts.
     */
    private void applyMigration2() throws SQLException {
        try (Statement st = conn.createStatement()) {
            addColumnIfMissing(st, "users", "kdf_version", "INTEGER NOT NULL DEFAULT 1");
            addColumnIfMissing(st, "vault_entries", "meta_iv", "TEXT");
            addColumnIfMissing(st, "vault_entries", "meta_cipher", "TEXT");

            // The plaintext metadata columns were NOT NULL in v1. SQLite cannot drop
            // a NOT NULL constraint in place, and they must accept NULL once a row is
            // migrated, so title is relaxed by rebuilding the table.
            relaxPlaintextMetadataColumns(st);
        }

        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (2, ?)")) {
            ps.setString(1, now());
            ps.executeUpdate();
        }
        LOG.info("Applied schema migration 2 (encrypted metadata + kdf_version)");
    }

    private void addColumnIfMissing(Statement st, String table, String column, String definition)
            throws SQLException {
        if (columnExists(table, column)) return;
        st.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition);
    }

    private boolean columnExists(String table, String column) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) return true;
            }
        }
        return false;
    }

    /** Rebuild vault_entries so the legacy plaintext metadata columns are nullable. */
    private void relaxPlaintextMetadataColumns(Statement st) throws SQLException {
        boolean titleNotNull = false;
        try (Statement probe = conn.createStatement();
             ResultSet rs = probe.executeQuery("PRAGMA table_info(vault_entries)")) {
            while (rs.next()) {
                if ("title".equalsIgnoreCase(rs.getString("name"))) {
                    titleNotNull = rs.getInt("notnull") == 1;
                }
            }
        }
        if (!titleNotNull) return;

        st.execute("""
            CREATE TABLE vault_entries_v2 (
                id              TEXT PRIMARY KEY,
                user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title           TEXT,
                entry_username  TEXT,
                url             TEXT,
                category        TEXT,
                is_favorite     INTEGER NOT NULL DEFAULT 0,
                meta_iv         TEXT,
                meta_cipher     TEXT,
                password_iv     TEXT NOT NULL,
                password_cipher TEXT NOT NULL,
                notes_iv        TEXT,
                notes_cipher    TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            )
            """);
        st.execute("""
            INSERT INTO vault_entries_v2
                (id, user_id, title, entry_username, url, category, is_favorite,
                 meta_iv, meta_cipher, password_iv, password_cipher,
                 notes_iv, notes_cipher, created_at, updated_at)
            SELECT id, user_id, title, entry_username, url, category, is_favorite,
                   meta_iv, meta_cipher, password_iv, password_cipher,
                   notes_iv, notes_cipher, created_at, updated_at
            FROM vault_entries
            """);
        st.execute("DROP TABLE vault_entries");
        st.execute("ALTER TABLE vault_entries_v2 RENAME TO vault_entries");
        st.execute("CREATE INDEX IF NOT EXISTS idx_entries_user ON vault_entries(user_id)");
    }

    // ─── KDF version ──────────────────────────────────────────────────────────

    public int getKdfVersion(String userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT kdf_version FROM users WHERE id = ?")) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 1;
            }
        }
    }

    public void setKdfVersion(String userId, int version) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE users SET kdf_version = ? WHERE id = ?")) {
            ps.setInt(1, version);
            ps.setString(2, userId);
            ps.executeUpdate();
        }
    }

    public Optional<User> findUserById(String userId) throws SQLException {
        String sql = "SELECT id, username, password_hash, password_salt, created_at, " +
                     "failed_attempts, locked_until FROM users WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapUser(rs));
            }
        }
        return Optional.empty();
    }

    // ─── Row Mappers ──────────────────────────────────────────────────────────

    private User mapUser(ResultSet rs) throws SQLException {
        String lockedUntilStr = rs.getString("locked_until");
        LocalDateTime lockedUntil = lockedUntilStr != null
            ? LocalDateTime.parse(lockedUntilStr, DT_FMT) : null;
        return new User(
            rs.getString("id"),
            rs.getString("username"),
            rs.getString("password_hash"),
            rs.getString("password_salt"),
            LocalDateTime.parse(rs.getString("created_at"), DT_FMT),
            rs.getInt("failed_attempts"),
            lockedUntil
        );
    }

    private EncryptedEntry mapEntry(ResultSet rs) throws SQLException {
        return new EncryptedEntry(
            rs.getString("id"),
            rs.getString("user_id"),
            rs.getInt("is_favorite") == 1,
            rs.getString("meta_iv"),
            rs.getString("meta_cipher"),
            rs.getString("password_iv"),
            rs.getString("password_cipher"),
            rs.getString("notes_iv"),
            rs.getString("notes_cipher"),
            LocalDateTime.parse(rs.getString("created_at"), DT_FMT),
            LocalDateTime.parse(rs.getString("updated_at"), DT_FMT)
        );
    }

    private String now() {
        return LocalDateTime.now().format(DT_FMT);
    }
}
