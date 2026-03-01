package com.passwordmanager.controllers;

import com.passwordmanager.App;
import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.GeneratorOptions;
import com.passwordmanager.models.VaultEntry;
import com.passwordmanager.services.CryptoService;
import com.passwordmanager.services.DatabaseService;
import com.passwordmanager.services.SessionService;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicReference;

public class VaultController {

    // Sidebar
    @FXML private Label usernameLabel;
    @FXML private Label sessionTimerLabel;
    @FXML private Button lockBtn;
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
    @FXML private Button favoriteBtn;

    private ObservableList<VaultEntry> allEntries = FXCollections.observableArrayList();
    private FilteredList<VaultEntry> filteredEntries;
    private VaultEntry selectedEntry;
    private Timer sessionCountdownTimer;
    private Timer revealTimer;
    private final long SESSION_TIMEOUT_MS = 15L * 60 * 1000;
    private long sessionStartMs;

    @FXML
    public void initialize() {
        sessionStartMs = System.currentTimeMillis();

        // Set username in sidebar
        try {
            var db = DatabaseService.getInstance();
            String uid = SessionService.getInstance().getUserId();
            db.findUserByUsername(db.findUserByUsername("") // placeholder approach
              .map(u -> u.username()).orElse(""));
        } catch (Exception ignored) {}

        setupCategoryList();
        setupEntryList();
        setupSearch();
        startSessionTimer();
        loadEntries();
    }

    private void setupCategoryList() {
        categoryList.getItems().addAll("All", "★ Favorites", "Login", "Card", "Note", "Identity", "Other");
        categoryList.getSelectionModel().select(0);
        categoryList.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            applyFilters();
        });
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
                    Label subLbl = new Label(item.entryUsername() != null ? item.entryUsername() : item.url() != null ? item.url() : item.category());
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

    private void applyFilters() {
        String search = searchField.getText().toLowerCase().trim();
        String category = categoryList.getSelectionModel().getSelectedItem();

        filteredEntries.setPredicate(entry -> {
            // Category filter
            if (category != null && !category.equals("All")) {
                if (category.equals("★ Favorites") && !entry.isFavorite()) return false;
                else if (!category.equals("★ Favorites") && !entry.category().equalsIgnoreCase(category)) return false;
            }
            // Search filter (title, username, url)
            if (!search.isEmpty()) {
                boolean matchTitle    = entry.title() != null && entry.title().toLowerCase().contains(search);
                boolean matchUser     = entry.entryUsername() != null && entry.entryUsername().toLowerCase().contains(search);
                boolean matchUrl      = entry.url() != null && entry.url().toLowerCase().contains(search);
                return matchTitle || matchUser || matchUrl;
            }
            return true;
        });

        emptyStateLabel.setVisible(filteredEntries.isEmpty());
    }

    private void loadEntries() {
        Thread.ofVirtual().start(() -> {
            try {
                String userId = SessionService.getInstance().getUserId();
                List<VaultEntry> entries = DatabaseService.getInstance().getEntriesForUser(userId);
                Platform.runLater(() -> {
                    allEntries.setAll(entries);
                    emptyStateLabel.setVisible(entries.isEmpty());
                });
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Error", "Failed to load entries: " + e.getMessage()));
            }
        });
    }

    private void showDetail(VaultEntry entry) {
        SessionService.getInstance().refresh();
        cancelRevealTimer();

        detailTitle.setText(entry.title());
        detailUsername.setText(entry.entryUsername() != null ? entry.entryUsername() : "—");
        detailUrl.setText(entry.url() != null ? entry.url() : "—");
        detailCategory.setText(entry.category());
        detailCreated.setText(entry.createdAt().toLocalDate().toString());
        detailPasswordMasked.setVisible(true);
        detailPasswordRevealed.setText("");
        detailPasswordRevealed.setVisible(false);
        revealPasswordBtn.setText("Reveal");

        favoriteBtn.setText(entry.isFavorite() ? "★ Unfavorite" : "☆ Favorite");

        if (entry.hasNotes()) {
            notesRow.setVisible(true);
            detailNotes.setText("••• (click to reveal)");
        } else {
            notesRow.setVisible(false);
        }

        detailScrollPane.setVisible(true);
        detailContent.setVisible(true);
        noSelectionPane.setVisible(false);
    }

    private void hideDetail() {
        detailScrollPane.setVisible(false);
        detailContent.setVisible(false);
        noSelectionPane.setVisible(true);
    }

    @FXML
    private void handleRevealPassword() {
        if (selectedEntry == null) return;
        SessionService.getInstance().refresh();

        if (detailPasswordRevealed.isVisible()) {
            // Re-hide
            detailPasswordRevealed.setText("");
            detailPasswordRevealed.setVisible(false);
            detailPasswordMasked.setVisible(true);
            revealPasswordBtn.setText("Reveal");
            cancelRevealTimer();
            return;
        }

        Thread.ofVirtual().start(() -> {
            try {
                byte[] key = SessionService.getInstance().getVaultKey();
                EncryptedData data = new EncryptedData(selectedEntry.passwordIv(), selectedEntry.passwordCipher());
                String decrypted = CryptoService.getInstance().decrypt(data, key);

                Platform.runLater(() -> {
                    detailPasswordRevealed.setText(decrypted);
                    detailPasswordRevealed.setVisible(true);
                    detailPasswordMasked.setVisible(false);
                    revealPasswordBtn.setText("Hide");

                    // Auto-hide after 30 seconds
                    scheduleRevealHide(30_000);
                });
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Error", "Could not decrypt password."));
            }
        });
    }

    @FXML
    private void handleCopyPassword() {
        if (selectedEntry == null) return;
        SessionService.getInstance().refresh();

        Thread.ofVirtual().start(() -> {
            try {
                byte[] key = SessionService.getInstance().getVaultKey();
                EncryptedData data = new EncryptedData(selectedEntry.passwordIv(), selectedEntry.passwordCipher());
                String decrypted = CryptoService.getInstance().decrypt(data, key);

                Platform.runLater(() -> {
                    ClipboardContent content = new ClipboardContent();
                    content.putString(decrypted);
                    Clipboard.getSystemClipboard().setContent(content);
                    copyPasswordBtn.setText("Copied!");

                    // Clear clipboard after 60 seconds
                    new Timer("clipboard-clear", true).schedule(new TimerTask() {
                        @Override public void run() {
                            Platform.runLater(() -> {
                                Clipboard.getSystemClipboard().setContent(new ClipboardContent());
                                copyPasswordBtn.setText("Copy");
                            });
                        }
                    }, 60_000);
                });
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Error", "Could not copy password."));
            }
        });
    }

    @FXML
    private void handleAddEntry() {
        SessionService.getInstance().refresh();
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/passwordmanager/fxml/add_edit_entry.fxml"));
            Parent root = loader.load();
            AddEditEntryController ctrl = loader.getController();
            ctrl.initForAdd();
            ctrl.setOnSave(() -> loadEntries());

            javafx.stage.Stage dialog = new javafx.stage.Stage();
            dialog.setTitle("Add Entry");
            dialog.initOwner(App.getPrimaryStage());
            dialog.initModality(javafx.stage.Modality.WINDOW_MODAL);
            javafx.scene.Scene scene = new javafx.scene.Scene(root, 480, 560);
            scene.getStylesheets().add(Objects.requireNonNull(
                getClass().getResource("/com/passwordmanager/css/app.css")).toExternalForm());
            dialog.setScene(scene);
            dialog.showAndWait();
        } catch (Exception e) {
            showAlert("Error", "Could not open add entry dialog: " + e.getMessage());
        }
    }

    @FXML
    private void handleEditEntry() {
        if (selectedEntry == null) return;
        SessionService.getInstance().refresh();
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/passwordmanager/fxml/add_edit_entry.fxml"));
            Parent root = loader.load();
            AddEditEntryController ctrl = loader.getController();
            ctrl.initForEdit(selectedEntry);
            ctrl.setOnSave(() -> {
                loadEntries();
                Platform.runLater(() -> entryListView.getSelectionModel().clearSelection());
            });

            javafx.stage.Stage dialog = new javafx.stage.Stage();
            dialog.setTitle("Edit Entry");
            dialog.initOwner(App.getPrimaryStage());
            dialog.initModality(javafx.stage.Modality.WINDOW_MODAL);
            javafx.scene.Scene scene = new javafx.scene.Scene(root, 480, 560);
            scene.getStylesheets().add(Objects.requireNonNull(
                getClass().getResource("/com/passwordmanager/css/app.css")).toExternalForm());
            dialog.setScene(scene);
            dialog.showAndWait();
        } catch (Exception e) {
            showAlert("Error", "Could not open edit dialog: " + e.getMessage());
        }
    }

    @FXML
    private void handleDeleteEntry() {
        if (selectedEntry == null) return;
        SessionService.getInstance().refresh();

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION,
            "Delete \"" + selectedEntry.title() + "\"? This cannot be undone.",
            ButtonType.YES, ButtonType.CANCEL);
        confirm.setTitle("Confirm Delete");
        confirm.setHeaderText(null);

        confirm.showAndWait().ifPresent(btn -> {
            if (btn == ButtonType.YES) {
                Thread.ofVirtual().start(() -> {
                    try {
                        DatabaseService.getInstance().deleteEntry(
                            selectedEntry.id(), SessionService.getInstance().getUserId()
                        );
                        Platform.runLater(() -> {
                            loadEntries();
                            hideDetail();
                        });
                    } catch (Exception e) {
                        Platform.runLater(() -> showAlert("Error", "Could not delete entry."));
                    }
                });
            }
        });
    }

    @FXML
    private void handleToggleFavorite() {
        if (selectedEntry == null) return;
        SessionService.getInstance().refresh();

        boolean newFav = !selectedEntry.isFavorite();
        Thread.ofVirtual().start(() -> {
            try {
                DatabaseService.getInstance().toggleFavorite(
                    selectedEntry.id(), SessionService.getInstance().getUserId(), newFav
                );
                loadEntries();
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Error", "Could not update favorite."));
            }
        });
    }

    @FXML
    private void handleLock() {
        cancelRevealTimer();
        stopSessionTimer();
        SessionService.getInstance().lock();
    }

    // ─── Session Timer ────────────────────────────────────────────────────────

    private void startSessionTimer() {
        sessionCountdownTimer = new Timer("session-countdown", true);
        sessionCountdownTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                long elapsed = System.currentTimeMillis() - sessionStartMs;
                long remaining = SESSION_TIMEOUT_MS - elapsed;
                if (remaining <= 0) {
                    cancel();
                    return;
                }
                long mins = remaining / 60000;
                long secs = (remaining % 60000) / 1000;
                String text = String.format("⏱ %d:%02d", mins, secs);
                Platform.runLater(() -> {
                    sessionTimerLabel.setText(text);
                    if (remaining < 120_000) {
                        sessionTimerLabel.getStyleClass().add("timer-warning");
                    } else {
                        sessionTimerLabel.getStyleClass().remove("timer-warning");
                    }
                });
            }
        }, 0, 1000);
    }

    private void stopSessionTimer() {
        if (sessionCountdownTimer != null) {
            sessionCountdownTimer.cancel();
        }
    }

    // ─── Reveal Timer ─────────────────────────────────────────────────────────

    private void scheduleRevealHide(long delayMs) {
        cancelRevealTimer();
        revealTimer = new Timer("reveal-hide", true);
        revealTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                Platform.runLater(() -> {
                    detailPasswordRevealed.setText("");
                    detailPasswordRevealed.setVisible(false);
                    detailPasswordMasked.setVisible(true);
                    revealPasswordBtn.setText("Reveal");
                });
            }
        }, delayMs);
    }

    private void cancelRevealTimer() {
        if (revealTimer != null) {
            revealTimer.cancel();
            revealTimer = null;
        }
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR, message, ButtonType.OK);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.showAndWait();
    }
}
