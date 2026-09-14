package com.passwordmanager.models;

import java.time.LocalDateTime;

/**
 * A vault entry exactly as it sits on disk — nothing here is readable without
 * the vault key.
 *
 * Title, account username, URL and category live together in one encrypted
 * metadata blob rather than in eight separate columns: one AES-GCM operation per
 * entry instead of four, and adding a metadata field later needs no migration.
 *
 * {@code isFavorite} and the timestamps stay in the clear. They are needed for
 * ORDER BY and cheap filtering, and a boolean plus a modification time leak far
 * less than an account name does.
 */
public record EncryptedEntry(
    String id,
    String userId,
    boolean isFavorite,
    String metaIv,          // base64 IV for the metadata blob
    String metaCipher,      // base64 AES-256-GCM ciphertext+tag of the metadata blob
    String passwordIv,
    String passwordCipher,
    String notesIv,         // nullable
    String notesCipher,     // nullable
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {}
