package com.passwordmanager.models;

import java.time.LocalDateTime;

public record VaultEntry(
    String id,
    String userId,
    String title,           // plaintext - shown in list, searchable
    String entryUsername,   // plaintext - account username/email
    String url,             // plaintext - site URL
    String category,        // plaintext - e.g. "Login", "Card", "Note"
    boolean isFavorite,
    String passwordIv,      // base64 IV for password encryption
    String passwordCipher,  // base64 AES-256-GCM ciphertext+tag
    String notesIv,         // base64 IV for notes (nullable)
    String notesCipher,     // base64 AES-256-GCM ciphertext+tag (nullable)
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {
    /** Returns true if this entry has encrypted notes. */
    public boolean hasNotes() {
        return notesIv != null && notesCipher != null;
    }
}
