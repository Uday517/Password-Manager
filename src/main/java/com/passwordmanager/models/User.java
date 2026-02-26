package com.passwordmanager.models;

import java.time.LocalDateTime;

public record User(
    String id,
    String username,
    String passwordHash,   // PBKDF2-SHA512 hash (base64)
    String passwordSalt,   // random 32-byte salt (base64)
    LocalDateTime createdAt,
    int failedAttempts,
    LocalDateTime lockedUntil  // null if not locked
) {}
