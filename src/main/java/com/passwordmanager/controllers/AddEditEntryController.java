package com.passwordmanager.controllers;

import com.passwordmanager.models.EncryptedData;
import com.passwordmanager.models.GeneratorOptions;
import com.passwordmanager.models.VaultEntry;
import com.passwordmanager.services.CryptoService;
import com.passwordmanager.services.DatabaseService;
import com.passwordmanager.services.SessionService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Slider;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.stage.Stage;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AddEditEntryController {

    private static final Logger LOG = Logger.getLogger(AddEditEntryController.class.getName());
    private static final int MAX_NOTES_LENGTH = 10_000;
    private static final int MAX_TITLE_LENGTH = 120;

    @FXML private Label titleLabel;
    @FXML private TextField titleField;
    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private TextField passwordVisible;
    @FXML private Button togglePasswordBtn;
    @FXML private TextField urlField;
    @FXML private ComboBox<String> categoryCombo;
    @FXML private CheckBox favoriteCheck;
    @FXML private TextArea notesArea;
    @FXML private Button saveBtn;
    @FXML private Button cancelBtn;
    @FXML private Label errorLabel;

    // Password generator
    @FXML private Slider lengthSlider;
    @FXML private Label lengthLabel;
    @FXML private CheckBox uppercaseCheck;
    @FXML private CheckBox lowercaseCheck;
    @FXML private CheckBox digitsCheck;
    @FXML private CheckBox specialCheck;
    @FXML private Button generateBtn;

    // Strength meter
    @FXML private HBox strengthRow;
    @FXML private Region strengthBar;
    @FXML private Label strengthLabel;

    private boolean isEditing;
    private VaultEntry editingEntry;
    private Runnable onSave;
    private boolean passwordShown = false;

    @FXML
    public void initialize() {
        categoryCombo.getItems().addAll("Login", "Card", "Note", "Identity", "Other");
        categoryCombo.getSelectionModel().select(0);

        errorLabel.setVisible(false);
        errorLabel.setManaged(false);
        strengthRow.setVisible(false);
        strengthRow.setManaged(false);

        // One source of truth for the password value: the two controls are
        // always mirrors of each other, only one is visible at a time.
        passwordVisible.textProperty().bindBidirectional(passwordField.textProperty());
        passwordVisible.textProperty().addListener((obs, oldVal, newVal) ->
            updateStrengthMeter(newVal));

        if (lengthSlider != null) {
            lengthSlider.valueProperty().addListener((obs, oldVal, newVal) ->
                lengthLabel.setText(String.valueOf(newVal.intValue())));
        }

        cancelBtn.setCancelButton(true);
        saveBtn.setDefaultButton(true);
        togglePasswordVisibility(false);
        Platform.runLater(titleField::requestFocus);
    }

    public void initForAdd() {
        isEditing = false;
        editingEntry = null;
        titleLabel.setText("Add Entry");
        saveBtn.setText("Save Entry");
    }

    public void initForEdit(VaultEntry entry) {
        isEditing = true;
        editingEntry = entry;
        titleLabel.setText("Edit Entry");
        saveBtn.setText("Update Entry");

        titleField.setText(entry.title());
        usernameField.setText(entry.entryUsername() != null ? entry.entryUsername() : "");
        urlField.setText(entry.url() != null ? entry.url() : "");
        categoryCombo.getSelectionModel().select(entry.category());
        favoriteCheck.setSelected(entry.isFavorite());

        // Load the existing encrypted values on a background thread.
        Thread.ofVirtual().start(() -> {
            try {
                byte[] key = SessionService.getInstance().getVaultKey();
                try {
                    String pwd = CryptoService.getInstance()
                        .decrypt(new EncryptedData(entry.passwordIv(), entry.passwordCipher()), key);
                    String notes = entry.hasNotes()
                        ? CryptoService.getInstance().decrypt(
                            new EncryptedData(entry.notesIv(), entry.notesCipher()), key)
                        : "";
                    Platform.runLater(() -> {
                        passwordVisible.setText(pwd);
                        notesArea.setText(notes);
                    });
                } finally {
                    Arrays.fill(key, (byte) 0);
                }
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Could not decrypt entry for editing", e);
                Platform.runLater(() -> showError("Could not decrypt the existing entry."));
            }
        });
    }

    public void setOnSave(Runnable onSave) {
        this.onSave = onSave;
    }

    @FXML
    private void handleTogglePassword() {
        togglePasswordVisibility(!passwordShown);
    }

    private void togglePasswordVisibility(boolean show) {
        passwordShown = show;
        passwordField.setVisible(!show);
        passwordField.setManaged(!show);
        passwordVisible.setVisible(show);
        passwordVisible.setManaged(show);
        togglePasswordBtn.setText(show ? "Hide" : "Show");
    }

    @FXML
    private void handleGenerate() {
        boolean anyClass = uppercaseCheck.isSelected() || lowercaseCheck.isSelected()
            || digitsCheck.isSelected() || specialCheck.isSelected();
        if (!anyClass) {
            showError("Select at least one character type.");
            return;
        }

        int length = lengthSlider != null ? (int) lengthSlider.getValue() : 20;
        GeneratorOptions opts = new GeneratorOptions(
            length,
            uppercaseCheck.isSelected(),
            lowercaseCheck.isSelected(),
            digitsCheck.isSelected(),
            specialCheck.isSelected()
        );

        try {
            String generated = CryptoService.getInstance().generatePassword(opts);
            passwordVisible.setText(generated);
            hideError();
        } catch (IllegalArgumentException e) {
            showError(e.getMessage());
        }
    }

    @FXML
    private void handleSave() {
        String title = titleField.getText().trim();
        String password = passwordVisible.getText();
        String username = usernameField.getText().trim();
        String url = urlField.getText().trim();
        String category = categoryCombo.getValue();
        boolean favorite = favoriteCheck.isSelected();
        String notes = notesArea.getText().trim();

        if (title.isBlank()) {
            showError("Title is required.");
            return;
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            showError("Title must be at most " + MAX_TITLE_LENGTH + " characters.");
            return;
        }
        if (password.isEmpty()) {
            showError("Password is required.");
            return;
        }
        if (notes.length() > MAX_NOTES_LENGTH) {
            showError("Notes must be at most " + MAX_NOTES_LENGTH + " characters.");
            return;
        }
        if (category == null || category.isBlank()) {
            category = "Login";
        }

        hideError();
        saveBtn.setDisable(true);
        saveBtn.setText("Saving...");

        final String chosenCategory = category;
        Thread.ofVirtual().start(() -> {
            try {
                byte[] key = SessionService.getInstance().getVaultKey();
                try {
                    EncryptedData encPwd = CryptoService.getInstance().encrypt(password, key);
                    String notesIv = null, notesCipher = null;
                    if (!notes.isEmpty()) {
                        EncryptedData encNotes = CryptoService.getInstance().encrypt(notes, key);
                        notesIv = encNotes.iv();
                        notesCipher = encNotes.ciphertext();
                    }

                    String userId = SessionService.getInstance().getUserId();
                    String finalUsername = username.isEmpty() ? null : username;
                    String finalUrl = url.isEmpty() ? null : url;

                    if (isEditing && editingEntry != null) {
                        DatabaseService.getInstance().updateEntry(
                            editingEntry.id(), userId, title, finalUsername, finalUrl,
                            chosenCategory, favorite,
                            encPwd.iv(), encPwd.ciphertext(),
                            notesIv, notesCipher
                        );
                    } else {
                        VaultEntry newEntry = new VaultEntry(
                            UUID.randomUUID().toString(), userId,
                            title, finalUsername, finalUrl, chosenCategory, favorite,
                            encPwd.iv(), encPwd.ciphertext(),
                            notesIv, notesCipher,
                            LocalDateTime.now(), LocalDateTime.now()
                        );
                        DatabaseService.getInstance().createEntry(newEntry);
                    }
                } finally {
                    Arrays.fill(key, (byte) 0);
                }

                Platform.runLater(() -> {
                    if (onSave != null) onSave.run();
                    closeDialog();
                });
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to save entry", e);
                Platform.runLater(() -> {
                    showError("Could not save the entry. Please try again.");
                    saveBtn.setDisable(false);
                    saveBtn.setText(isEditing ? "Update Entry" : "Save Entry");
                });
            }
        });
    }

    @FXML
    private void handleCancel() {
        closeDialog();
    }

    private void closeDialog() {
        // Drop the plaintext from the UI before the window goes away.
        passwordVisible.setText("");
        notesArea.setText("");
        Stage stage = (Stage) saveBtn.getScene().getWindow();
        stage.close();
    }

    private void showError(String msg) {
        Platform.runLater(() -> {
            errorLabel.setText(msg);
            errorLabel.setVisible(true);
            errorLabel.setManaged(true);
        });
    }

    private void hideError() {
        errorLabel.setVisible(false);
        errorLabel.setManaged(false);
    }

    private void updateStrengthMeter(String password) {
        if (strengthRow == null) return;
        if (password == null || password.isEmpty()) {
            strengthRow.setVisible(false);
            strengthRow.setManaged(false);
            return;
        }
        strengthRow.setVisible(true);
        strengthRow.setManaged(true);
        int score = CryptoService.getInstance().passwordStrength(password);
        String[] labels = {"Very Weak", "Weak", "Fair", "Strong", "Very Strong"};
        String[] styles = {"strength-very-weak", "strength-weak", "strength-fair",
                           "strength-strong", "strength-very-strong"};
        strengthLabel.setText(labels[score]);
        strengthBar.getStyleClass().removeIf(s -> s.startsWith("strength-"));
        strengthBar.getStyleClass().add(styles[score]);
        strengthBar.setPrefWidth(60.0 + score * 55.0);
    }
}
