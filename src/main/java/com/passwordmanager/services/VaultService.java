package com.passwordmanager.services;

import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.EncryptedEntry;
import com.passwordmanager.models.VaultEntry;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The only place that turns encrypted rows into readable entries and back.
 *
 * Controllers deal in {@link VaultEntry} (decrypted metadata, still-encrypted
 * secrets); {@link DatabaseService} deals in {@link EncryptedEntry}. Keeping the
 * conversion here means neither of those two knows about the other's concerns,
 * and there is exactly one implementation of the metadata format to audit.
 */
public class VaultService {

    private static VaultService instance;

    private VaultService() {}

    public static synchronized VaultService getInstance() {
        if (instance == null) {
            instance = new VaultService();
        }
        return instance;
    }

    // ─── Metadata codec ───────────────────────────────────────────────────────
    //
    // Length-prefixed rather than delimiter-joined: a title containing whatever
    // separator we picked would otherwise corrupt every field after it, and a
    // vault is exactly the place someone stores a string full of odd characters.
    // Format: "<len>:<value>" per field, or "-1:" for null.

    static String encodeMeta(String... fields) {
        StringBuilder sb = new StringBuilder();
        for (String f : fields) {
            if (f == null) {
                sb.append("-1:");
            } else {
                sb.append(f.length()).append(':').append(f);
            }
        }
        return sb.toString();
    }

    static String[] decodeMeta(String encoded, int fieldCount) {
        String[] out = new String[fieldCount];
        int pos = 0;
        for (int i = 0; i < fieldCount; i++) {
            int colon = encoded.indexOf(':', pos);
            if (colon < 0) throw new IllegalArgumentException("Malformed metadata blob");
            int len = Integer.parseInt(encoded.substring(pos, colon));
            pos = colon + 1;
            if (len < 0) {
                out[i] = null;
            } else {
                if (pos + len > encoded.length()) {
                    throw new IllegalArgumentException("Malformed metadata blob");
                }
                out[i] = encoded.substring(pos, pos + len);
                pos += len;
            }
        }
        return out;
    }

    // ─── Read ─────────────────────────────────────────────────────────────────

    /** Load and decrypt every entry for the session's user. */
    public List<VaultEntry> listEntries(String userId, byte[] vaultKey) throws Exception {
        List<EncryptedEntry> rows = DatabaseService.getInstance().getEntriesForUser(userId);
        List<VaultEntry> out = new ArrayList<>(rows.size());
        for (EncryptedEntry row : rows) {
            out.add(decrypt(row, vaultKey));
        }
        return out;
    }

    public Optional<VaultEntry> getEntry(String entryId, String userId, byte[] vaultKey)
            throws Exception {
        Optional<EncryptedEntry> row = DatabaseService.getInstance().getEntry(entryId, userId);
        if (row.isEmpty()) return Optional.empty();
        return Optional.of(decrypt(row.get(), vaultKey));
    }

    private VaultEntry decrypt(EncryptedEntry row, byte[] vaultKey) throws Exception {
        String blob = CryptoService.getInstance()
            .decrypt(new EncryptedData(row.metaIv(), row.metaCipher()), vaultKey);
        String[] meta = decodeMeta(blob, 4);
        return new VaultEntry(
            row.id(), row.userId(),
            meta[0], meta[1], meta[2], meta[3],
            row.isFavorite(),
            row.passwordIv(), row.passwordCipher(),
            row.notesIv(), row.notesCipher(),
            row.createdAt(), row.updatedAt()
        );
    }

    /** Decrypt a single secret field (password or notes) on demand. */
    public String reveal(String iv, String cipher, byte[] vaultKey) throws Exception {
        return CryptoService.getInstance().decrypt(new EncryptedData(iv, cipher), vaultKey);
    }

    // ─── Write ────────────────────────────────────────────────────────────────

    public void createEntry(String userId, byte[] vaultKey, String title, String username,
                            String url, String category, boolean favorite,
                            String password, String notes) throws Exception {
        DatabaseService.getInstance().createEntry(
            build(UUID.randomUUID().toString(), userId, vaultKey, title, username, url,
                  category, favorite, password, notes));
    }

    public void updateEntry(String entryId, String userId, byte[] vaultKey, String title,
                            String username, String url, String category, boolean favorite,
                            String password, String notes) throws Exception {
        DatabaseService.getInstance().updateEntry(
            build(entryId, userId, vaultKey, title, username, url,
                  category, favorite, password, notes));
    }

    private EncryptedEntry build(String id, String userId, byte[] vaultKey, String title,
                                 String username, String url, String category, boolean favorite,
                                 String password, String notes) throws Exception {
        CryptoService crypto = CryptoService.getInstance();
        EncryptedData meta = crypto.encrypt(encodeMeta(title, username, url, category), vaultKey);
        EncryptedData pwd = crypto.encrypt(password, vaultKey);

        String notesIv = null, notesCipher = null;
        if (notes != null && !notes.isEmpty()) {
            EncryptedData encNotes = crypto.encrypt(notes, vaultKey);
            notesIv = encNotes.iv();
            notesCipher = encNotes.ciphertext();
        }

        LocalDateTime nowTs = LocalDateTime.now();
        return new EncryptedEntry(id, userId, favorite, meta.iv(), meta.ciphertext(),
            pwd.iv(), pwd.ciphertext(), notesIv, notesCipher, nowTs, nowTs);
    }

    public void deleteEntry(String entryId, String userId) throws Exception {
        DatabaseService.getInstance().deleteEntry(entryId, userId);
    }

    public void toggleFavorite(String entryId, String userId, boolean favorite) throws Exception {
        DatabaseService.getInstance().toggleFavorite(entryId, userId, favorite);
    }
}
