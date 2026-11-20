package com.passwordmanager.controllers;

import com.passwordmanager.App;
import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.VaultEntry;
import com.passwordmanager.services.CryptoService;
import com.passwordmanager.services.DatabaseService;
import com.passwordmanager.services.SecurityAuditService;
import com.passwordmanager.services.SessionService;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.input.ScrollEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VaultController {

    private static final Logger LOG = Logger.getLogger(VaultController.class.getName());
    private static final long SECRET_REVEAL_MS = 30_000;
    private static final long CLIPBOARD_CLEAR_MS = 60_000;

    // Sidebar
    @FXML private Label usernameLabel;
    @FXML private Label sessionTimerLabel;
    @FXML private Button lockBtn;
    @FXML private Button auditBtn;
    @FXML private ListView<String> categoryList;

    // Search + toolbar
    @FXML private TextField searchField;
    @FXML private Button addEntryBtn;

    // Entry list
    @FXML private ListView<VaultEntry> entryListView;
    @FXML private Label emptyStateLabel;

    // Entry detail panel
    @FXML private StackPane detailPane;
    @FXML private ScrollPane detailScrollPane;
    @FXML private VBox detailContent;
    @FXML private VBox noSelectionPane;
    @FXML private Label detailTitle;
    @FXML private Label detailUsername;
    @FXML private Label detailUrl;
    @FXML private Label detailCategory;
    @FXML private Label detailCreated;
    @FXML private Label detailPasswordMasked;
    @FXML private Label detailPasswordRevealed;
    @FXML private Button revealPasswordBtn;
    @FXML private Button copyPasswordBtn;
    @FXML private Button editEntryBtn;
    @FXML private Button deleteEntryBtn;
    @FXML private HBox notesRow;
    @FXML private Label detailNotes;
    @FXML private Button notesRevealBtn;
    @FXML private Button favoriteBtn;

    private final ObservableList<VaultEntry> allEntries = FXCollections.observableArrayList();
    private FilteredList<VaultEntry> filteredEntries;
    private VaultEntry selectedEntry;

    private Timer sessionCountdownTimer;
    private Timer revealTimer;
    private Timer clipboardTimer;
    private String clipboardSecret;

    @FXML
    public void initialize() {
        usernameLabel.setText("@" + SessionService.getInstance().getUsername());

        setupCategoryList();
        setupEntryList();
        setupSearch();
        startSessionTimer();
        trackActivity();
        loadEntries();
    }

    // ─── Setup ────────────────────────────────────────────────────────────────

    private void setupCategoryList() {
        categoryList.getItems().addAll("All", "★ Favorites", "Login", "Card", "Note", "Identity", "Other");
        categoryList.getSelectionModel().select(0);
        categoryList.getSelectionModel().selectedItemProperty().addListener(
            (obs, oldVal, newVal) -> applyFilters());
    }

    private void setupEntryList() {
        filteredEntries = new FilteredList<>(allEntries);
        entryListView.setItems(filteredEntries);

        entryListView.setCellFactory(lv -> new ListCell<>() {
            @Override
            protected void updateItem(VaultEntry item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                    getStyleClass().remove("entry-cell");
                } else {
                    getStyleClass().add("entry-cell");
                    VBox box = new VBox(2);
                    Label titleLbl = new Label(item.title());
                    titleLbl.getStyleClass().add("entry-title");
                    String subtitle = item.entryUsername() != null ? item.entryUsername()
                        : item.url() != null ? item.url() : item.category();
                    Label subLbl = new Label(subtitle);
                    subLbl.getStyleClass().add("entry-subtitle");
                    box.getChildren().addAll(titleLbl, subLbl);
                    setGraphic(box);
                    setText(null);
                }
            }
        });

        entryListView.getSelectionModel().selectedItemProperty().addListener((obs, old, entry) -> {
            selectedEntry = entry;
            if (entry != null) showDetail(entry);
            else hideDetail();
        });
    }

    private void setupSearch() {
        searchField.textProperty().addListener((obs, oldVal, newVal) -> applyFilters());
    }

    /** Any click, key press or scroll in the vault resets the idle timer. */
    private void trackActivity() {
        Platform.runLater(() -> {
            Scene scene = entryListView.getScene();
            if (scene == null) return;
            javafx.event.EventHandler<javafx.event.Event> refresh =
                event -> SessionService.getInstance().refresh();
            scene.addEventFilter(MouseEvent.MOUSE_PRESSED, refresh);
            scene.addEventFilter(KeyEvent.KEY_PRESSED, refresh);
            scene.addEventFilter(ScrollEvent.SCROLL, refresh);
        });
    }

    private void applyFilters() {
        String search = searchField.getText().toLowerCase(Locale.ROOT).trim();
        String category = categoryList.getSelectionModel().getSelectedItem();

        filteredEntries.setPredicate(entry -> {
            if (category != null && !category.equals("All")) {
                if (category.equals("★ Favorites") && !entry.isFavorite()) return false;
                else if (!category.equals("★ Favorites") && !entry.category().equalsIgnoreCase(category)) return false;
            }
            if (!search.isEmpty()) {
                boolean matchTitle = entry.title() != null
                    && entry.title().toLowerCase(Locale.ROOT).contains(search);
                boolean matchUser = entry.entryUsername() != null
                    && entry.entryUsername().toLowerCase(Locale.ROOT).contains(search);
                boolean matchUrl = entry.url() != null
                    && entry.url().toLowerCase(Locale.ROOT).contains(search);
                return matchTitle || matchUser || matchUrl;
            }
            return true;
        });

        boolean empty = filteredEntries.isEmpty();
        emptyStateLabel.setVisible(empty);
        emptyStateLabel.setManaged(empty);
    }

    private void loadEntries() {
        Thread.ofVirtual().start(() -> {
            try {
                String userId = SessionService.getInstance().getUserId();
                List<VaultEntry> entries = DatabaseService.getInstance().getEntriesForUser(userId);
                Platform.runLater(() -> {
                    allEntries.setAll(entries);
                    emptyStateLabel.setVisible(entries.isEmpty());
                    emptyStateLabel.setManaged(entries.isEmpty());
                });
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to load entries", e);
                Platform.runLater(() -> showAlert("Could not load entries. Please try again."));
            }
        });
    }

    // ─── Detail panel ─────────────────────────────────────────────────────────

    private void showDetail(VaultEntry entry) {
        SessionService.getInstance().refresh();
        hideAllSecrets();

        detailTitle.setText(entry.title());
        detailUsername.setText(entry.entryUsername() != null ? entry.entryUsername() : "—");
        detailUrl.setText(entry.url() != null ? entry.url() : "—");
        detailCategory.setText(entry.category());
        detailCreated.setText(entry.createdAt().toLocalDate().toString());
        favoriteBtn.setText(entry.isFavorite() ? "★ Unfavorite" : "☆ Favorite");

        if (entry.hasNotes()) {
            notesRow.setVisible(true);
            notesRow.setManaged(true);
            detailNotes.setText("••• Hidden — click Reveal");
            notesRevealBtn.setText("Reveal");
        } else {
            notesRow.setVisible(false);
            notesRow.setManaged(false);
            detailNotes.setText("");
        }

        detailScrollPane.setVisible(true);
        detailContent.setVisible(true);
        noSelectionPane.setVisible(false);
    }

    private void hideDetail() {
        hideAllSecrets();
        detailScrollPane.setVisible(false);
        detailContent.setVisible(false);
        noSelectionPane.setVisible(true);
    }

    private void hideAllSecrets() {
        cancelRevealTimer();
        detailPasswordRevealed.setText("");
        detailPasswordRevealed.setVisible(false);
        detailPasswordMasked.setVisible(true);
        revealPasswordBtn.setText("Reveal");
        if (notesRevealBtn != null) {
            notesRevealBtn.setText("Reveal");
        }
        if (detailNotes != null && selectedEntry != null && selectedEntry.hasNotes()) {
            detailNotes.setText("••• Hidden — click Reveal");
        }
    }

    @FXML
    private void handleRevealPassword() {
        VaultEntry entry = selectedEntry;
        if (entry == null) return;
        SessionService.getInstance().refresh();

        if (detailPasswordRevealed.isVisible()) {
            hideAllSecrets();
            return;
        }

        Thread.ofVirtual().start(() -> {
            try {
                String decrypted = decryptField(entry.passwordIv(), entry.passwordCipher());
                Platform.runLater(() -> {
                    if (selectedEntry == null || !selectedEntry.id().equals(entry.id())) return;
                    detailPasswordRevealed.setText(decrypted);
                    detailPasswordRevealed.setVisible(true);
                    detailPasswordMasked.setVisible(false);
                    revealPasswordBtn.setText("Hide");
                    scheduleSecretHide();
                });
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to decrypt password", e);
                Platform.runLater(() -> showAlert("Could not decrypt this password."));
            }
        });
    }

    @FXML
    private void handleRevealNotes() {
        VaultEntry entry = selectedEntry;
        if (entry == null || !entry.hasNotes()) return;
        SessionService.getInstance().refresh();

        boolean alreadyVisible = !detailNotes.getText().startsWith("•••");
        if (alreadyVisible) {
            hideAllSecrets();
            return;
        }

        Thread.ofVirtual().start(() -> {
            try {
                String decrypted = decryptField(entry.notesIv(), entry.notesCipher());
                Platform.runLater(() -> {
                    if (selectedEntry == null || !selectedEntry.id().equals(entry.id())) return;
                    detailNotes.setText(decrypted);
                    notesRevealBtn.setText("Hide");
                    scheduleSecretHide();
                });
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to decrypt notes", e);
                Platform.runLater(() -> showAlert("Could not decrypt these notes."));
            }
        });
    }

    @FXML
    private void handleCopyPassword() {
        VaultEntry entry = selectedEntry;
        if (entry == null) return;
        SessionService.getInstance().refresh();

        Thread.ofVirtual().start(() -> {
            try {
                String decrypted = decryptField(entry.passwordIv(), entry.passwordCipher());
                Platform.runLater(() -> copySecretToClipboard(decrypted));
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to copy password", e);
                Platform.runLater(() -> showAlert("Could not copy this password."));
            }
        });
    }

    private void copySecretToClipboard(String secret) {
        ClipboardContent content = new ClipboardContent();
        content.putString(secret);
        Clipboard.getSystemClipboard().setContent(content);

        clipboardSecret = secret;
        copyPasswordBtn.setText("Copied");

        if (clipboardTimer != null) clipboardTimer.cancel();
        clipboardTimer = new Timer("clipboard-clear", true);
        clipboardTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                Platform.runLater(() -> {
                    // Only clear the clipboard if it still holds our secret. Never
                    // destroy something the user copied in the meantime.
                    Clipboard clipboard = Clipboard.getSystemClipboard();
                    if (secret.equals(clipboard.getString())) {
                        clipboard.clear();
                    }
                    if (secret.equals(clipboardSecret)) {
                        clipboardSecret = null;
                        copyPasswordBtn.setText("Copy");
                    }
                });
            }
        }, CLIPBOARD_CLEAR_MS);
    }

    private void clearClipboardIfOwned() {
        if (clipboardTimer != null) {
            clipboardTimer.cancel();
            clipboardTimer = null;
        }
        if (clipboardSecret != null) {
            Clipboard clipboard = Clipboard.getSystemClipboard();
            if (clipboardSecret.equals(clipboard.getString())) {
                clipboard.clear();
            }
            clipboardSecret = null;
        }
    }

    // ─── Entry actions ────────────────────────────────────────────────────────

    @FXML
    private void handleAddEntry() {
        SessionService.getInstance().refresh();
        openEntryDialog(null);
    }

    @FXML
    private void handleEditEntry() {
        if (selectedEntry == null) return;
        SessionService.getInstance().refresh();
        openEntryDialog(selectedEntry);
    }

    private void openEntryDialog(VaultEntry entry) {
        try {
            FXMLLoader loader = new FXMLLoader(
                getClass().getResource("/com/passwordmanager/fxml/add_edit_entry.fxml"));
            Parent root = loader.load();
            AddEditEntryController ctrl = loader.getController();
            if (entry == null) {
                ctrl.initForAdd();
            } else {
                ctrl.initForEdit(entry);
            }
            ctrl.setOnSave(this::loadEntries);

            Stage dialog = new Stage();
            dialog.setTitle(entry == null ? "Add Entry" : "Edit Entry");
            dialog.initOwner(App.getPrimaryStage());
            dialog.initModality(Modality.WINDOW_MODAL);
            dialog.setResizable(false);
            Scene scene = new Scene(root, 480, 820);
            scene.getStylesheets().add(Objects.requireNonNull(
                getClass().getResource("/com/passwordmanager/css/app.css")).toExternalForm());
            dialog.setScene(scene);
            dialog.showAndWait();

            // A modal dialog can sit open longer than the idle timeout.
            SessionService.getInstance().refresh();
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Failed to open entry dialog", e);
            showAlert("Could not open the entry dialog.");
        }
    }

    @FXML
    private void handleDeleteEntry() {
        VaultEntry entry = selectedEntry;
        if (entry == null) return;
        SessionService.getInstance().refresh();

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION,
            "Delete \"" + entry.title() + "\"? This cannot be undone.",
            ButtonType.YES, ButtonType.CANCEL);
        confirm.setTitle("Confirm Delete");
        confirm.setHeaderText(null);
        confirm.initOwner(App.getPrimaryStage());
        styleDialog(confirm);

        confirm.showAndWait().ifPresent(btn -> {
            if (btn == ButtonType.YES) {
                Thread.ofVirtual().start(() -> {
                    try {
                        DatabaseService.getInstance().deleteEntry(
                            entry.id(), SessionService.getInstance().getUserId());
                        Platform.runLater(() -> {
                            selectedEntry = null;
                            hideDetail();
                            loadEntries();
                        });
                    } catch (Exception e) {
                        LOG.log(Level.WARNING, "Failed to delete entry", e);
                        Platform.runLater(() -> showAlert("Could not delete the entry."));
                    }
                });
            }
        });
    }

    @FXML
    private void handleToggleFavorite() {
        VaultEntry entry = selectedEntry;
        if (entry == null) return;
        SessionService.getInstance().refresh();

        boolean newFav = !entry.isFavorite();
        Thread.ofVirtual().start(() -> {
            try {
                DatabaseService.getInstance().toggleFavorite(
                    entry.id(), SessionService.getInstance().getUserId(), newFav);
                Platform.runLater(() -> {
                    favoriteBtn.setText(newFav ? "★ Unfavorite" : "☆ Favorite");
                    loadEntries();
                });
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to update favorite", e);
                Platform.runLater(() -> showAlert("Could not update the favorite."));
            }
        });
    }

    @FXML
    private void handleLock() {
        cancelRevealTimer();
        stopSessionTimer();
        hideAllSecrets();
        clearClipboardIfOwned();
        allEntries.clear();
        selectedEntry = null;
        SessionService.getInstance().lock();
    }

    // ─── Security audit ───────────────────────────────────────────────────────

    @FXML
    private void handleSecurityAudit() {
        SessionService.getInstance().refresh();

        Thread.ofVirtual().start(() -> {
            try {
                String userId = SessionService.getInstance().getUserId();
                List<VaultEntry> entries = DatabaseService.getInstance().getEntriesForUser(userId);
                List<SecurityAuditService.Input> inputs = new ArrayList<>(entries.size());
                int decryptFailures = 0;

                for (VaultEntry entry : entries) {
                    try {
                        String password = decryptField(entry.passwordIv(), entry.passwordCipher());
                        inputs.add(new SecurityAuditService.Input(
                            entry.title(), password, entry.updatedAt()));
                    } catch (Exception e) {
                        decryptFailures++;
                    }
                }

                SecurityAuditService.Report report =
                    SecurityAuditService.audit(inputs, LocalDate.now());
                final int failures = decryptFailures;
                Platform.runLater(() -> showAuditReport(report, failures));
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Security audit failed", e);
                Platform.runLater(() -> showAlert("Could not run the security check."));
            }
        });
    }

    private void showAuditReport(SecurityAuditService.Report report, int decryptFailures) {
        if (report.total() == 0) {
            Alert empty = new Alert(Alert.AlertType.INFORMATION,
                "Add some entries first — there is nothing to analyse yet.", ButtonType.OK);
            empty.setTitle("Security Check");
            empty.setHeaderText(null);
            empty.initOwner(App.getPrimaryStage());
            styleDialog(empty);
            empty.showAndWait();
            return;
        }

        VBox content = new VBox(10);
        content.getStyleClass().add("audit-content");

        Label score = new Label("Vault hygiene score: " + report.score() + " / 100");
        score.getStyleClass().add("audit-score");

        Label summary = new Label(report.healthy() + " of " + report.total()
            + " entries have no issues found.");
        summary.getStyleClass().add("audit-summary");

        content.getChildren().addAll(
            score, summary,
            auditLine("Weak passwords", report.weak(), report.weakTitles()),
            auditLine("Reused passwords", report.reused(), report.reusedTitles()),
            auditLine("Shared password groups", report.reusedGroups() + " group"
                + (report.reusedGroups() == 1 ? "" : "s"), List.of()),
            auditLine("Not changed in " + SecurityAuditService.STALE_AFTER_DAYS + " days",
                report.stale(), report.staleTitles()),
            auditLine("Oldest password", report.oldestDays() + " days", List.of())
        );

        if (decryptFailures > 0) {
            Label failed = new Label(decryptFailures + " entr"
                + (decryptFailures == 1 ? "y" : "ies") + " could not be decrypted and were skipped.");
            failed.getStyleClass().add("audit-warning");
            failed.setWrapText(true);
            content.getChildren().add(failed);
        }

        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Security Check");
        alert.setHeaderText(null);
        alert.getDialogPane().setContent(content);
        alert.getDialogPane().setPrefWidth(520);
        alert.initOwner(App.getPrimaryStage());
        styleDialog(alert);
        alert.showAndWait();
    }

    private VBox auditLine(String label, int count, List<String> titles) {
        return auditLine(label, String.valueOf(count), titles);
    }

    private VBox auditLine(String label, String value, List<String> details) {
        Label name = new Label(label);
        name.getStyleClass().add("audit-label");
        name.setMaxWidth(Double.MAX_VALUE);
        name.setMinWidth(0);
        name.setWrapText(true);

        Label amount = new Label(value);
        amount.getStyleClass().add("audit-value");
        amount.setMinWidth(Region.USE_PREF_SIZE);

        HBox header = new HBox(10, name, amount);
        header.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(name, Priority.ALWAYS);

        VBox row = new VBox(3, header);
        row.getStyleClass().add("audit-row");
        row.setMaxWidth(Double.MAX_VALUE);

        if (!details.isEmpty()) {
            Label detail = new Label(String.join(", ", details.stream().limit(4).toList())
                + (details.size() > 4 ? ", …" : ""));
            detail.getStyleClass().add("audit-detail");
            detail.setWrapText(true);
            detail.setMinWidth(0);
            row.getChildren().add(detail);
        }
        return row;
    }

    // ─── Timers ───────────────────────────────────────────────────────────────

    private void startSessionTimer() {
        sessionCountdownTimer = new Timer("session-countdown", true);
        sessionCountdownTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                SessionService session = SessionService.getInstance();
                if (!session.isActive()) {
                    cancel();
                    return;
                }
                long remaining = session.getRemainingIdleMillis();
                long mins = remaining / 60_000;
                long secs = (remaining % 60_000) / 1000;
                String text = String.format("⏱ %d:%02d", mins, secs);
                boolean warning = remaining < 120_000;

                Platform.runLater(() -> {
                    sessionTimerLabel.setText(text);
                    if (warning) {
                        if (!sessionTimerLabel.getStyleClass().contains("timer-warning")) {
                            sessionTimerLabel.getStyleClass().add("timer-warning");
                        }
                    } else {
                        sessionTimerLabel.getStyleClass().remove("timer-warning");
                    }
                });
            }
        }, 0, 1_000);
    }

    private void stopSessionTimer() {
        if (sessionCountdownTimer != null) {
            sessionCountdownTimer.cancel();
            sessionCountdownTimer = null;
        }
    }

    private void scheduleSecretHide() {
        cancelRevealTimer();
        revealTimer = new Timer("reveal-hide", true);
        revealTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                Platform.runLater(VaultController.this::hideAllSecrets);
            }
        }, SECRET_REVEAL_MS);
    }

    private void cancelRevealTimer() {
        if (revealTimer != null) {
            revealTimer.cancel();
            revealTimer = null;
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private String decryptField(String iv, String ciphertext) throws Exception {
        byte[] key = SessionService.getInstance().getVaultKey();
        try {
            return CryptoService.getInstance()
                .decrypt(new EncryptedData(iv, ciphertext), key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private void styleDialog(Alert alert) {
        alert.getDialogPane().getStylesheets().add(Objects.requireNonNull(
            getClass().getResource("/com/passwordmanager/css/app.css")).toExternalForm());
        alert.getDialogPane().getStyleClass().add("dialog-root");
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR, message, ButtonType.OK);
        alert.setTitle("Vault");
        alert.setHeaderText(null);
        alert.initOwner(App.getPrimaryStage());
        styleDialog(alert);
        alert.showAndWait();
    }
}
