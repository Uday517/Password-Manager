package com.passwordmanager.services;

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
        Files.createDirectories(dbPath.getParent());

        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();
        conn = DriverManager.getConnection(url);

        // Set restrictive file permissions on POSIX systems (Linux/macOS)
        try {
            File dbFile = dbPath.toFile();
            if (dbFile.exists()) {
                Files.setPosixFilePermissions(dbPath, PosixFilePermissions.fromString("rw-------"));
            }
        } catch (UnsupportedOperationException e) {
            // Windows does not support POSIX permissions — skip
        }

        // Performance and safety pragmas
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("PRAGMA foreign_keys=ON");
            st.execute("PRAGMA synchronous=NORMAL");
        }

        runMigrations();
        LOG.info("Database initialized at: " + dbPath);
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

    public List<VaultEntry> getEntriesForUser(String userId) throws SQLException {
        String sql = "SELECT id, user_id, title, entry_username, url, category, is_favorite, " +
                     "password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at " +
                     "FROM vault_entries WHERE user_id = ? ORDER BY updated_at DESC";
        List<VaultEntry> entries = new ArrayList<>();
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

    public Optional<VaultEntry> getEntry(String entryId, String userId) throws SQLException {
        String sql = "SELECT id, user_id, title, entry_username, url, category, is_favorite, " +
                     "password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at " +
                     "FROM vault_entries WHERE id = ? AND user_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, entryId);
            ps.setString(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapEntry(rs));
            }
        }
        return Optional.empty();
    }

    public void createEntry(VaultEntry entry) throws SQLException {
        String sql = "INSERT INTO vault_entries " +
                     "(id, user_id, title, entry_username, url, category, is_favorite, " +
                     " password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1,  entry.id());
            ps.setString(2,  entry.userId());
            ps.setString(3,  entry.title());
            ps.setString(4,  entry.entryUsername());
            ps.setString(5,  entry.url());
            ps.setString(6,  entry.category());
            ps.setInt(7,     entry.isFavorite() ? 1 : 0);
            ps.setString(8,  entry.passwordIv());
            ps.setString(9,  entry.passwordCipher());
            ps.setString(10, entry.notesIv());
            ps.setString(11, entry.notesCipher());
            ps.setString(12, now());
            ps.setString(13, now());
            ps.executeUpdate();
        }
    }

    public void updateEntry(String entryId, String userId, String title, String entryUsername,
                            String url, String category, boolean isFavorite,
                            String passwordIv, String passwordCipher,
                            String notesIv, String notesCipher) throws SQLException {
        String sql = "UPDATE vault_entries SET title=?, entry_username=?, url=?, category=?, " +
                     "is_favorite=?, password_iv=?, password_cipher=?, notes_iv=?, notes_cipher=?, " +
                     "updated_at=? WHERE id=? AND user_id=?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1,  title);
            ps.setString(2,  entryUsername);
            ps.setString(3,  url);
            ps.setString(4,  category);
            ps.setInt(5,     isFavorite ? 1 : 0);
            ps.setString(6,  passwordIv);
            ps.setString(7,  passwordCipher);
            ps.setString(8,  notesIv);
            ps.setString(9,  notesCipher);
            ps.setString(10, now());
            ps.setString(11, entryId);
            ps.setString(12, userId);
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

    private VaultEntry mapEntry(ResultSet rs) throws SQLException {
        return new VaultEntry(
            rs.getString("id"),
            rs.getString("user_id"),
            rs.getString("title"),
            rs.getString("entry_username"),
            rs.getString("url"),
            rs.getString("category"),
            rs.getInt("is_favorite") == 1,
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
