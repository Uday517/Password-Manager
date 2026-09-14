package com.passwordmanager.models;

import java.time.LocalDateTime;

/**
 * A decrypted vault entry, as the UI sees it.
 *
 * Instances of this record only ever exist in memory and only while a session is
 * unlocked — {@code title}, {@code entryUsername}, {@code url} and
 * {@code category} are plaintext here but are stored encrypted (see
 * {@link EncryptedEntry}). The password and notes stay encrypted even in this
 * object; they are decrypted individually, on demand, when the user asks to
 * reveal or copy them.
 */
public record VaultEntry(
    String id,
    String userId,
    String title,           // decrypted in memory
    String entryUsername,   // decrypted in memory
    String url,             // decrypted in memory
    String category,        // decrypted in memory
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
