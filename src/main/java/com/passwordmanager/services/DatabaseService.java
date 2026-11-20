package com.passwordmanager.services;

import com.passwordmanager.models.User;
import com.passwordmanager.models.VaultEntry;
import com.passwordmanager.utils.AppPaths;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * All database operations for the password manager.
 *
 * Security design:
 * - Every query uses PreparedStatement — zero string concatenation in SQL
 * - WAL mode with synchronous=FULL for crash safety
 * - Foreign keys enforced at the DB level
 * - Data directory 0700, database and side files 0600 on POSIX systems
 * - secure_delete so removed rows do not linger in free pages
 * - Schema versioned via a schema_migrations table
 *
 * Thread safety: SQLite JDBC connections are not safe for concurrent use.
 * Every public method is synchronized so the virtual-thread callers in the
 * controllers are serialized onto the single connection.
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

    public synchronized void initialize() throws Exception {
        if (conn != null && !conn.isClosed()) {
            return;
        }

        Path dbPath = AppPaths.getDatabasePath();
        Path dataDir = dbPath.getParent();
        if (dataDir == null) {
            throw new IOException("Database path has no parent directory: " + dbPath);
        }
        Files.createDirectories(dataDir);
        hardenDirectory(dataDir);

        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();
        conn = DriverManager.getConnection(url);

        try {
            // Performance and safety pragmas
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA foreign_keys=ON");
                st.execute("PRAGMA synchronous=FULL");
                st.execute("PRAGMA busy_timeout=5000");
                st.execute("PRAGMA secure_delete=ON");
                st.execute("PRAGMA journal_size_limit=67108864");
                st.execute("PRAGMA trusted_schema=OFF");
            }

            runMigrations();
            hardenFiles(dbPath);
        } catch (Exception e) {
            closeQuietly();
            throw e;
        }

        LOG.info("Database initialized at: " + dbPath);
    }

    public synchronized void close() {
        if (conn != null) {
            try {
                if (!conn.isClosed()) {
                    conn.close();
                }
            } catch (SQLException e) {
                LOG.log(Level.WARNING, "Error closing database", e);
            } finally {
                conn = null;
            }
        }
    }

    public synchronized boolean hasAnyUser() throws SQLException {
        try (PreparedStatement ps = requireConn().prepareStatement("SELECT COUNT(*) FROM users");
             ResultSet rs = ps.executeQuery()) {
            return rs.next() && rs.getInt(1) > 0;
        }
    }

    // ─── Users ────────────────────────────────────────────────────────────────

    public synchronized Optional<User> findUserByUsername(String username) throws SQLException {
        String sql = "SELECT id, username, password_hash, password_salt, created_at, " +
                     "failed_attempts, locked_until FROM users WHERE username = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapUser(rs));
                }
            }
        }
        return Optional.empty();
    }

    public synchronized Optional<User> findUserById(String id) throws SQLException {
        String sql = "SELECT id, username, password_hash, password_salt, created_at, " +
                     "failed_attempts, locked_until FROM users WHERE id = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapUser(rs));
                }
            }
        }
        return Optional.empty();
    }

    public synchronized void createUser(String id, String username, String passwordHash,
                                        String passwordSalt) throws SQLException {
        String sql = "INSERT INTO users (id, username, password_hash, password_salt, created_at) " +
                     "VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, username);
            ps.setString(3, passwordHash);
            ps.setString(4, passwordSalt);
            ps.setString(5, now());
            ps.executeUpdate();
        }
        hardenSideFiles();
    }

    public synchronized void incrementFailedAttempts(String userId) throws SQLException {
        String sql = "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, userId);
            ps.executeUpdate();
        }
        hardenSideFiles();
    }

    public synchronized void lockUser(String userId, LocalDateTime until) throws SQLException {
        String sql = "UPDATE users SET locked_until = ? WHERE id = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, until.format(DT_FMT));
            ps.setString(2, userId);
            ps.executeUpdate();
        }
        hardenSideFiles();
    }

    public synchronized void resetFailedAttempts(String userId) throws SQLException {
        String sql = "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, userId);
            ps.executeUpdate();
        }
        hardenSideFiles();
    }

    // ─── Vault Entries ────────────────────────────────────────────────────────

    public synchronized List<VaultEntry> getEntriesForUser(String userId) throws SQLException {
        String sql = "SELECT id, user_id, title, entry_username, url, category, is_favorite, " +
                     "password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at " +
                     "FROM vault_entries WHERE user_id = ? ORDER BY updated_at DESC";
        List<VaultEntry> entries = new ArrayList<>();
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    entries.add(mapEntry(rs));
                }
            }
        }
        return entries;
    }

    public synchronized Optional<VaultEntry> getEntry(String entryId, String userId)
            throws SQLException {
        String sql = "SELECT id, user_id, title, entry_username, url, category, is_favorite, " +
                     "password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at " +
                     "FROM vault_entries WHERE id = ? AND user_id = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, entryId);
            ps.setString(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapEntry(rs));
            }
        }
        return Optional.empty();
    }

    public synchronized void createEntry(VaultEntry entry) throws SQLException {
        String sql = "INSERT INTO vault_entries " +
                     "(id, user_id, title, entry_username, url, category, is_favorite, " +
                     " password_iv, password_cipher, notes_iv, notes_cipher, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
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
        hardenSideFiles();
    }

    public synchronized void updateEntry(String entryId, String userId, String title,
                                         String entryUsername, String url, String category,
                                         boolean isFavorite, String passwordIv, String passwordCipher,
                                         String notesIv, String notesCipher) throws SQLException {
        String sql = "UPDATE vault_entries SET title=?, entry_username=?, url=?, category=?, " +
                     "is_favorite=?, password_iv=?, password_cipher=?, notes_iv=?, notes_cipher=?, " +
                     "updated_at=? WHERE id=? AND user_id=?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
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
        hardenSideFiles();
    }

    public synchronized void deleteEntry(String entryId, String userId) throws SQLException {
        String sql = "DELETE FROM vault_entries WHERE id = ? AND user_id = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setString(1, entryId);
            ps.setString(2, userId);
            ps.executeUpdate();
        }
        hardenSideFiles();
    }

    public synchronized void toggleFavorite(String entryId, String userId, boolean isFavorite)
            throws SQLException {
        String sql = "UPDATE vault_entries SET is_favorite = ? WHERE id = ? AND user_id = ?";
        try (PreparedStatement ps = requireConn().prepareStatement(sql)) {
            ps.setInt(1, isFavorite ? 1 : 0);
            ps.setString(2, entryId);
            ps.setString(3, userId);
            ps.executeUpdate();
        }
        hardenSideFiles();
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

    private Connection requireConn() throws SQLException {
        if (conn == null || conn.isClosed()) {
            throw new SQLException("Database is not initialized");
        }
        return conn;
    }

    private void closeQuietly() {
        try {
            if (conn != null) conn.close();
        } catch (SQLException ignored) {
            // already failing; nothing useful to do
        } finally {
            conn = null;
        }
    }

    // ─── File permissions ─────────────────────────────────────────────────────

    private static void hardenDirectory(Path dir) {
        try {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        } catch (UnsupportedOperationException | IOException e) {
            // Windows or a filesystem without POSIX permissions — skip
        }
    }

    private void hardenSideFiles() {
        hardenFiles(AppPaths.getDatabasePath());
    }

    private static void hardenFiles(Path dbPath) {
        setOwnerOnly(dbPath);
        setOwnerOnly(dbPath.resolveSibling(dbPath.getFileName() + "-wal"));
        setOwnerOnly(dbPath.resolveSibling(dbPath.getFileName() + "-shm"));
        setOwnerOnly(dbPath.resolveSibling(dbPath.getFileName() + "-journal"));
    }

    private static void setOwnerOnly(Path file) {
        try {
            if (Files.exists(file)) {
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            }
        } catch (UnsupportedOperationException | IOException e) {
            // Windows or a filesystem without POSIX permissions — skip
        }
    }

    // ─── Test hooks ───────────────────────────────────────────────────────────

    /** Closes the connection and forgets the singleton. Test suites only. */
    static synchronized void resetForTests() {
        if (instance != null) {
            instance.close();
            instance = null;
        }
    }
}
