package com.passwordmanager.services;

import com.passwordmanager.models.EncryptedData;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * Converts a KDF v1 vault to v2, in the one moment the master password is in hand.
 *
 * v1 stored the vault key behind a separate 100,000-iteration PBKDF2 pass while the
 * auth hash cost 600,000 — so the cheapest attack on a stolen database ignored the
 * auth hash entirely. v1 also left title, account username, URL and category in
 * plaintext columns. v2 fixes both: the vault key becomes bytes 32-63 of a single
 * 600k derivation, and the metadata moves into an encrypted blob.
 *
 * The stored auth hash needs no rewrite. PBKDF2 emits T1||T2||…, so the first 32
 * bytes of the new 64-byte derivation are bit-identical to the 32-byte hash v1
 * wrote. Only the entries are re-encrypted.
 *
 * Everything happens in one transaction: either the whole vault is v2 or the
 * database is untouched and the user logs in against v1 exactly as before.
 */
public class VaultMigrationService {

    private static final Logger LOG = Logger.getLogger(VaultMigrationService.class.getName());
    public static final int CURRENT_KDF_VERSION = 2;

    private VaultMigrationService() {}

    /**
     * Bring this user up to KDF v2 if they are not already there.
     *
     * @param userId    the authenticated user
     * @param saltB64   their stored salt
     * @param password  the master password, already verified. Not cleared here.
     * @param newKey    the v2 vault key (bytes 32-63 of the 600k derivation)
     * @return true if a migration ran, false if the user was already v2
     */
    public static boolean migrateIfNeeded(String userId, String saltB64, char[] password,
                                          byte[] newKey) throws Exception {
        DatabaseService db = DatabaseService.getInstance();
        if (db.getKdfVersion(userId) >= CURRENT_KDF_VERSION) return false;

        CryptoService crypto = CryptoService.getInstance();

        @SuppressWarnings("deprecation")
        byte[] oldKey = crypto.deriveVaultKeyV1(password, saltB64);
        try {
            List<DatabaseService.LegacyEntryRow> rows = db.getLegacyEntries(userId);
            LOG.info("Migrating " + rows.size() + " entries to KDF v2 for user " + userId);

            db.inTransaction(() -> {
                for (DatabaseService.LegacyEntryRow row : rows) {
                    // Read under the old key...
                    String password0 = crypto.decrypt(
                        new EncryptedData(row.passwordIv(), row.passwordCipher()), oldKey);

                    String notes = null;
                    if (row.notesIv() != null && row.notesCipher() != null) {
                        notes = crypto.decrypt(
                            new EncryptedData(row.notesIv(), row.notesCipher()), oldKey);
                    }

                    // ...and write it back under the new one, metadata included.
                    EncryptedData newMeta = crypto.encrypt(
                        VaultService.encodeMeta(row.title(), row.entryUsername(),
                                                row.url(), row.category()), newKey);
                    EncryptedData newPassword = crypto.encrypt(password0, newKey);

                    String notesIv = null, notesCipher = null;
                    if (notes != null) {
                        EncryptedData newNotes = crypto.encrypt(notes, newKey);
                        notesIv = newNotes.iv();
                        notesCipher = newNotes.ciphertext();
                    }

                    db.writeMigratedEntry(row.id(), userId, newMeta.iv(), newMeta.ciphertext(),
                        newPassword.iv(), newPassword.ciphertext(), notesIv, notesCipher);
                }
                db.setKdfVersion(userId, CURRENT_KDF_VERSION);
            });

            // Nulling the plaintext columns only unlinks them — the old page content
            // stays in the file until it is rebuilt. VACUUM has to run after the
            // commit, since SQLite refuses it inside a transaction.
            db.vacuum();

            LOG.info("KDF v2 migration complete for user " + userId);
            return true;
        } finally {
            Arrays.fill(oldKey, (byte) 0);
        }
    }
}
