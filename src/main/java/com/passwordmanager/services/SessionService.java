package com.passwordmanager.services;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages the authenticated session including the in-memory vault key.
 *
 * Security design:
 * - The vault key lives only in this singleton — it is never written to disk.
 * - Callers receive a copy from {@link #getVaultKey()} and must zero it.
 * - On lock/logout/timeout the authoritative key is zeroed with Arrays.fill.
 * - A daemon watchdog locks the session after a period of inactivity.
 * - The lock callback runs on the locking thread; it must marshal to the UI
 *   thread itself (App::showLogin does this with Platform.runLater).
 */
public class SessionService {

    private static final Logger LOG = Logger.getLogger(SessionService.class.getName());
    private static final long DEFAULT_IDLE_TIMEOUT_MS = 15L * 60 * 1000;  // 15 minutes
    private static final long WATCHDOG_PERIOD_MS = 250;

    private static SessionService instance;

    private final Object lock = new Object();
    private final ScheduledExecutorService watchdog;

    private String userId;
    private String username;
    private byte[] vaultKey;
    private Runnable onLockCallback;
    private volatile boolean active;
    private volatile long lastActivityNanos;
    private volatile long idleTimeoutMs;

    private SessionService() {
        this.idleTimeoutMs = configuredTimeout();
        this.watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = Thread.ofPlatform().daemon().name("vault-idle-watchdog").unstarted(r);
            return t;
        });
        watchdog.scheduleAtFixedRate(this::checkIdle, WATCHDOG_PERIOD_MS,
                                     WATCHDOG_PERIOD_MS, TimeUnit.MILLISECONDS);
    }

    public static synchronized SessionService getInstance() {
        if (instance == null) {
            instance = new SessionService();
        }
        return instance;
    }

    /**
     * Create a new authenticated session.
     *
     * @param userId   the authenticated user's ID
     * @param username the display name for the vault UI
     * @param vaultKey 32-byte AES key (copied; the caller keeps ownership)
     * @param onLock   called when the session times out or is manually locked
     */
    public void create(String userId, String username, byte[] vaultKey, Runnable onLock) {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(username, "username");
        if (vaultKey == null || vaultKey.length != 32) {
            throw new IllegalArgumentException("Vault key must be 32 bytes");
        }

        byte[] copy = Arrays.copyOf(vaultKey, vaultKey.length);
        synchronized (lock) {
            destroyInternalLocked();
            this.userId = userId;
            this.username = username;
            this.vaultKey = copy;
            this.onLockCallback = onLock;
            this.lastActivityNanos = System.nanoTime();
            this.active = true;
        }
        LOG.info("Session created");
    }

    /**
     * Returns a copy of the vault key. The caller is responsible for zeroing the
     * returned array as soon as it is no longer needed.
     */
    public byte[] getVaultKey() {
        synchronized (lock) {
            if (!active || vaultKey == null) {
                throw new IllegalStateException("No active session");
            }
            return Arrays.copyOf(vaultKey, vaultKey.length);
        }
    }

    public String getUserId() {
        synchronized (lock) {
            if (!active) throw new IllegalStateException("No active session");
            return userId;
        }
    }

    public String getUsername() {
        synchronized (lock) {
            if (!active) throw new IllegalStateException("No active session");
            return username;
        }
    }

    public boolean isActive() {
        return active;
    }

    /** Reset the idle timer. Call this on any user interaction. */
    public void refresh() {
        if (active) {
            lastActivityNanos = System.nanoTime();
        }
    }

    /** Milliseconds until the idle lock fires, or 0 when no session is active. */
    public long getRemainingIdleMillis() {
        if (!active) return 0;
        long elapsedMs = (System.nanoTime() - lastActivityNanos) / 1_000_000;
        return Math.max(0, idleTimeoutMs - elapsedMs);
    }

    public long getIdleTimeoutMillis() {
        return idleTimeoutMs;
    }

    /** Manually lock the session (for example the Lock button). */
    public void lock() {
        end(true);
    }

    /** Destroy the session without triggering the lock callback (app shutdown). */
    public void destroy() {
        end(false);
    }

    private void checkIdle() {
        try {
            if (active && getRemainingIdleMillis() <= 0) {
                LOG.info("Session timed out due to inactivity");
                end(true);
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "Idle watchdog failed", e);
        }
    }

    private void end(boolean notify) {
        Runnable callback;
        synchronized (lock) {
            if (!active) return;
            callback = notify ? onLockCallback : null;
            destroyInternalLocked();
        }
        if (callback != null) {
            try {
                callback.run();
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "Session lock callback failed", e);
            }
        }
        LOG.info(notify ? "Session locked" : "Session destroyed");
    }

    private void destroyInternalLocked() {
        if (vaultKey != null) {
            Arrays.fill(vaultKey, (byte) 0);  // zero the key before it is released
            vaultKey = null;
        }
        userId = null;
        username = null;
        onLockCallback = null;
        active = false;
    }

    private static long configuredTimeout() {
        try {
            long configured = Long.getLong("vault.idle.timeout.ms", DEFAULT_IDLE_TIMEOUT_MS);
            return configured > 0 ? configured : DEFAULT_IDLE_TIMEOUT_MS;
        } catch (SecurityException | NumberFormatException e) {
            return DEFAULT_IDLE_TIMEOUT_MS;
        }
    }

    // ─── Test hooks ───────────────────────────────────────────────────────────

    static synchronized void resetForTests() {
        if (instance != null) {
            instance.end(false);
            instance.watchdog.shutdownNow();
            instance = null;
        }
    }

    void setIdleTimeoutForTests(long millis) {
        if (millis <= 0) {
            throw new IllegalArgumentException("Timeout must be positive");
        }
        idleTimeoutMs = millis;
    }
}
