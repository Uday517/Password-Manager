package com.passwordmanager.services;

import com.passwordmanager.models.User;

import java.sql.SQLException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Authentication and registration policy, independent of the JavaFX layer.
 *
 * Keeping this logic here (instead of in controllers) makes the security
 * behaviour deterministic and unit-testable: lockout, attempt counting,
 * username enumeration resistance, password policy and duplicate handling.
 */
public class AuthService {

    private static final Logger LOG = Logger.getLogger(AuthService.class.getName());

    public static final int MAX_ATTEMPTS = 5;
    public static final int LOCKOUT_MINUTES = 30;
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 128;

    private static AuthService instance;

    private final DatabaseService db = DatabaseService.getInstance();
    private final CryptoService crypto = CryptoService.getInstance();

    private AuthService() {}

    public static synchronized AuthService getInstance() {
        if (instance == null) {
            instance = new AuthService();
        }
        return instance;
    }

    public enum Status { SUCCESS, INVALID_CREDENTIALS, LOCKED }

    /**
     * @param remainingAttempts attempts left after this failure, or -1 when the
     *                           username does not exist (no information leak)
     * @param lockoutMinutes     minutes until the account unlocks, 0 otherwise
     */
    public record LoginResult(Status status, User user, int remainingAttempts, long lockoutMinutes) {
        static LoginResult success(User user) {
            return new LoginResult(Status.SUCCESS, user, MAX_ATTEMPTS, 0);
        }

        static LoginResult invalid(int remainingAttempts) {
            return new LoginResult(Status.INVALID_CREDENTIALS, null, remainingAttempts, 0);
        }

        static LoginResult locked(long minutes) {
            return new LoginResult(Status.LOCKED, null, 0, Math.max(1, minutes));
        }
    }

    /** Thrown for user-correctable registration errors. The message is safe to display. */
    public static class AuthException extends Exception {
        public AuthException(String message) {
            super(message);
        }
    }

    /**
     * Verify credentials and update the persisted lockout state.
     * This method never throws for wrong credentials; it returns a result.
     */
    public LoginResult authenticate(String username, char[] password) throws Exception {
        if (username == null || username.isBlank()) {
            return LoginResult.invalid(0);
        }

        Optional<User> userOpt = db.findUserByUsername(username.trim());
        if (userOpt.isEmpty()) {
            // Burn the same PBKDF2 cost as a real check so response time does
            // not reveal whether the username exists.
            crypto.simulatePasswordCheck(password);
            return LoginResult.invalid(-1);
        }

        User user = userOpt.get();
        LocalDateTime now = LocalDateTime.now();

        if (user.lockedUntil() != null) {
            if (now.isBefore(user.lockedUntil())) {
                long minutes = Duration.between(now, user.lockedUntil()).toMinutes() + 1;
                return LoginResult.locked(minutes);
            }
            // Lockout expired: start from a clean counter.
            db.resetFailedAttempts(user.id());
            user = db.findUserById(user.id()).orElse(user);
        }

        boolean valid;
        try {
            valid = crypto.verifyMasterPassword(password, user.passwordSalt(), user.passwordHash());
        } catch (IllegalArgumentException e) {
            // Corrupt/tampered credential row must fail closed.
            LOG.log(Level.WARNING, "Stored credential record is invalid", e);
            valid = false;
        }

        if (!valid) {
            int attempts = user.failedAttempts() + 1;
            db.incrementFailedAttempts(user.id());

            if (attempts >= MAX_ATTEMPTS) {
                db.lockUser(user.id(), now.plusMinutes(LOCKOUT_MINUTES));
                return LoginResult.locked(LOCKOUT_MINUTES);
            }
            return LoginResult.invalid(MAX_ATTEMPTS - attempts);
        }

        db.resetFailedAttempts(user.id());
        return LoginResult.success(user);
    }

    /**
     * Validate the registration fields, hash the master password and persist the
     * user. The caller is responsible for creating the session and deriving the
     * vault key.
     */
    public User register(String username, char[] password) throws AuthException, SQLException {
        String name = username == null ? "" : username.trim();

        if (name.isEmpty()) {
            throw new AuthException("Username is required.");
        }
        if (name.length() < 3 || name.length() > 50) {
            throw new AuthException("Username must be between 3 and 50 characters.");
        }
        if (!name.matches("[a-zA-Z0-9_.-]+")) {
            throw new AuthException(
                "Username may only contain letters, digits, underscores, dots and hyphens.");
        }
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new AuthException(
                "Master password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new AuthException(
                "Master password must be at most " + MAX_PASSWORD_LENGTH + " characters.");
        }
        if (crypto.passwordStrength(password) < 2) {
            throw new AuthException(
                "Master password is too weak. Use a mix of letters, numbers and symbols.");
        }
        if (db.findUserByUsername(name).isPresent()) {
            throw new AuthException("Username already taken. Please choose another.");
        }

        String[] hashResult;
        try {
            hashResult = crypto.hashMasterPassword(password);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("Could not hash the master password", e);
        }
        String salt = hashResult[0];
        String hash = hashResult[1];

        String userId = UUID.randomUUID().toString();
        try {
            db.createUser(userId, name, hash, salt);
        } catch (SQLException e) {
            // The UNIQUE constraint closes the race between check and insert.
            if (e.getMessage() != null && e.getMessage().toLowerCase().contains("unique")) {
                throw new AuthException("Username already taken. Please choose another.");
            }
            throw e;
        }

        return new User(userId, name, hash, salt, LocalDateTime.now(), 0, null);
    }

    // ─── Test hooks ───────────────────────────────────────────────────────────

    static synchronized void resetForTests() {
        instance = null;
    }
}
