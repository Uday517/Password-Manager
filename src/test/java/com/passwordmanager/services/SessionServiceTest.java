package com.passwordmanager.services;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionServiceTest {

    private SessionService session;

    @BeforeEach
    void setUp() {
        SessionService.resetForTests();
        session = SessionService.getInstance();
    }

    @AfterEach
    void tearDown() {
        SessionService.resetForTests();
    }

    @Test
    void createExposesStateAndReturnsKeyCopies() {
        byte[] key = key((byte) 7);
        session.setIdleTimeoutForTests(60_000);
        session.create("user-1", "alice", key, () -> {});

        assertTrue(session.isActive());
        assertEquals("user-1", session.getUserId());
        assertEquals("alice", session.getUsername());

        byte[] copy = session.getVaultKey();
        copy[0] = 99;
        assertArrayEquals(key((byte) 7), session.getVaultKey(),
            "mutating a returned key must not change the session key");

        session.destroy();
        assertFalse(session.isActive());
        assertThrows(IllegalStateException.class, session::getVaultKey);
    }

    @Test
    void timesOutAfterInactivityAndNotifies() throws Exception {
        session.setIdleTimeoutForTests(400);
        CountDownLatch locked = new CountDownLatch(1);
        session.create("user-1", "alice", key((byte) 1), locked::countDown);

        assertTrue(locked.await(10, TimeUnit.SECONDS), "session should auto-lock");
        assertFalse(session.isActive());
    }

    @Test
    void refreshExtendsTheIdleDeadline() throws Exception {
        // Generous margins so a loaded CI runner cannot make this flaky.
        session.setIdleTimeoutForTests(1_500);
        CountDownLatch locked = new CountDownLatch(1);
        session.create("user-1", "alice", key((byte) 1), locked::countDown);

        Thread.sleep(400);
        session.refresh();
        Thread.sleep(700);
        assertTrue(session.isActive(), "refresh should have moved the deadline");

        assertTrue(locked.await(10, TimeUnit.SECONDS));
    }

    @Test
    void remainingTimeCountsDown() throws Exception {
        session.setIdleTimeoutForTests(5_000);
        session.create("user-1", "alice", key((byte) 1), () -> {});

        long before = session.getRemainingIdleMillis();
        Thread.sleep(100);
        long after = session.getRemainingIdleMillis();

        assertTrue(before > 0 && before <= 5_000);
        assertTrue(after < before);
    }

    @Test
    void manualLockNotifiesExactlyOnce() {
        AtomicInteger locks = new AtomicInteger();
        session.setIdleTimeoutForTests(60_000);
        session.create("user-1", "alice", key((byte) 1), locks::incrementAndGet);

        session.lock();
        session.lock();

        assertEquals(1, locks.get());
        assertFalse(session.isActive());
    }

    @Test
    void destroyDoesNotNotify() {
        AtomicInteger locks = new AtomicInteger();
        session.setIdleTimeoutForTests(60_000);
        session.create("user-1", "alice", key((byte) 1), locks::incrementAndGet);

        session.destroy();

        assertEquals(0, locks.get());
        assertFalse(session.isActive());
    }

    @Test
    void rejectsInvalidKeysAndUseWithoutSession() {
        assertThrows(IllegalArgumentException.class,
            () -> session.create("user-1", "alice", new byte[16], () -> {}));
        assertThrows(IllegalStateException.class, session::getUserId);
        assertThrows(IllegalStateException.class, session::getUsername);
        assertEquals(0, session.getRemainingIdleMillis());
    }

    private static byte[] key(byte value) {
        byte[] key = new byte[32];
        Arrays.fill(key, value);
        return key;
    }
}
