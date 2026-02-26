package com.passwordmanager.models;

/**
 * Holds AES-256-GCM encrypted data.
 * The ciphertext field includes the GCM authentication tag appended by Java's cipher.
 */
public record EncryptedData(
    String iv,         // base64-encoded 12-byte IV (96 bits for GCM)
    String ciphertext  // base64-encoded ciphertext + 16-byte GCM auth tag
) {}
