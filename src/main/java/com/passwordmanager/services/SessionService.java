package com.passwordmanager.services;

import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

/**
 * Manages the authenticated session including the in-memory vault key.
 *
 * Security design:
 * - The vault key (byte[]) lives ONLY in this singleton — never written to disk
 * - On lock/logout: the key is zeroed with Arrays.fill before null-assignment
 * - Idle timer fires after IDLE_TIMEOUT_MS of no activity
 * - Any vault operation should call refresh() to reset the idle timer
 * - The lock callback is invoked on the calling thread (caller must use Platform.runLater if UI)
 */
public class SessionService {

    private static final Logger LOG = Logger.getLogger(SessionService.class.getName());
    private static final long IDLE_TIMEOUT_MS = 15L * 60 * 1000;  // 15 minutes

    private static SessionService instance;

    private String userId;
    private byte[] vaultKey;
    private Timer idleTimer;
    private Runnable onLockCallback;
    private final AtomicBoolean active = new AtomicBoolean(false);

    private SessionService() {}

    public static synchronized SessionService getInstance() {
        if (instance == null) {
            instance = new SessionService();
        }
        return instance;
    }

    /**
     * Create a new authenticated session.
     *
     * @param userId       the authenticated user's ID
     * @param vaultKey     32-byte AES key (this service takes ownership — will zero it on destroy)
     * @param onLock       called when the session times out or is manually locked
     */
    public synchronized void create(String userId, byte[] vaultKey, Runnable onLock) {
        destroyInternal();  // clear any existing session first
        this.userId = userId;
        this.vaultKey = Arrays.copyOf(vaultKey, vaultKey.length);
        this.onLockCallback = onLock;
        active.set(true);
        scheduleIdleTimer();
        LOG.info("Session created for user: " + userId);
    }

    /** Returns the vault key. Throws IllegalStateException if no active session. */
    public synchronized byte[] getVaultKey() {
        if (!active.get() || vaultKey == null) {
            throw new IllegalStateException("No active session");
        }
        return vaultKey;
    }

    public String getUserId() {
        if (!active.get()) throw new IllegalStateException("No active session");
        return userId;
    }

    public boolean isActive() {
        return active.get();
    }

    /** Reset the idle timer. Call this on any user interaction. */
    public synchronized void refresh() {
        if (active.get()) {
            cancelIdleTimer();
            scheduleIdleTimer();
        }
    }

    /** Manually lock the session (e.g. lock button clicked). */
    public void lock() {
        destroyInternal();
        if (onLockCallback != null) {
            onLockCallback.run();
        }
    }

    /** Destroy the session without triggering the lock callback (logout). */
    public void destroy() {
        destroyInternal();
    }

    private synchronized void destroyInternal() {
        cancelIdleTimer();
        if (vaultKey != null) {
            Arrays.fill(vaultKey, (byte) 0);  // zero the key before GC
            vaultKey = null;
        }
        userId = null;
        active.set(false);
        LOG.info("Session destroyed");
    }

    private void scheduleIdleTimer() {
        idleTimer = new Timer("idle-lock-timer", true);
        idleTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                LOG.info("Session timed out due to inactivity");
                Runnable cb = onLockCallback;
                destroyInternal();
                if (cb != null) cb.run();
            }
        }, IDLE_TIMEOUT_MS);
    }

    private void cancelIdleTimer() {
        if (idleTimer != null) {
            idleTimer.cancel();
            idleTimer = null;
        }
    }
}
