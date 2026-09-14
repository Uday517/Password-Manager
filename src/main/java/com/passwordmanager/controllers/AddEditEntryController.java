package com.passwordmanager.controllers;

import com.passwordmanager.models.GeneratorOptions;
import com.passwordmanager.models.VaultEntry;
import com.passwordmanager.services.CryptoService;
import com.passwordmanager.services.SessionService;
import com.passwordmanager.services.VaultService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.stage.Stage;

public class AddEditEntryController {

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
    private boolean passwordVisible2 = false;

    @FXML
    public void initialize() {
        categoryCombo.getItems().addAll("Login", "Card", "Note", "Identity", "Other");
        categoryCombo.getSelectionModel().select(0);

        errorLabel.setVisible(false);
        strengthRow.setVisible(false);

        // Sync visible/masked password fields
        passwordField.textProperty().addListener((obs, o, n) -> {
            if (!passwordVisible2) passwordVisible.setText(n);
            updateStrengthMeter(n);
        });
        passwordVisible.textProperty().addListener((obs, o, n) -> {
            if (passwordVisible2) passwordField.setText(n);
        });

        // Generator slider
        if (lengthSlider != null) {
            lengthSlider.valueProperty().addListener((obs, o, n) ->
                lengthLabel.setText(String.valueOf(n.intValue())));
        }

        togglePasswordVisibility(false);
    }

    public void initForAdd() {
        isEditing = false;
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

        // Load existing encrypted password
        Thread.ofVirtual().start(() -> {
            try {
                byte[] key = SessionService.getInstance().getVaultKey();
                VaultService vault = VaultService.getInstance();
                String pwd = vault.reveal(entry.passwordIv(), entry.passwordCipher(), key);
                Platform.runLater(() -> passwordField.setText(pwd));

                if (entry.hasNotes()) {
                    String notes = vault.reveal(entry.notesIv(), entry.notesCipher(), key);
                    Platform.runLater(() -> notesArea.setText(notes));
                }
            } catch (Exception e) {
                Platform.runLater(() -> showError("Could not decrypt existing password."));
            }
        });
    }

    public void setOnSave(Runnable onSave) {
        this.onSave = onSave;
    }

    @FXML
    private void handleTogglePassword() {
        togglePasswordVisibility(!passwordVisible2);
    }

    private void togglePasswordVisibility(boolean show) {
        passwordVisible2 = show;
        passwordField.setVisible(!show);
        passwordField.setManaged(!show);
        passwordVisible.setVisible(show);
        passwordVisible.setManaged(show);
        togglePasswordBtn.setText(show ? "Hide" : "Show");
        if (show) {
            passwordVisible.setText(passwordField.getText());
        } else {
            passwordField.setText(passwordVisible.getText());
        }
    }

    @FXML
    private void handleGenerate() {
        int length = lengthSlider != null ? (int) lengthSlider.getValue() : 20;
        GeneratorOptions opts = new GeneratorOptions(
            length,
            uppercaseCheck != null && uppercaseCheck.isSelected(),
            lowercaseCheck != null && lowercaseCheck.isSelected(),
            digitsCheck != null && digitsCheck.isSelected(),
            specialCheck != null && specialCheck.isSelected()
        );
        String generated = CryptoService.getInstance().generatePassword(opts);
        passwordField.setText(generated);
        passwordVisible.setText(generated);
    }

    @FXML
    private void handleSave() {
        String title = titleField.getText().trim();
        String password = passwordVisible2 ? passwordVisible.getText() : passwordField.getText();
        String username = usernameField.getText().trim();
        String url = urlField.getText().trim();
        String category = categoryCombo.getValue();
        boolean favorite = favoriteCheck.isSelected();
        String notes = notesArea.getText().trim();

        if (title.isBlank()) {
            showError("Title is required.");
            return;
        }
        if (password.isEmpty()) {
            showError("Password is required.");
            return;
        }

        errorLabel.setVisible(false);
        saveBtn.setDisable(true);
        saveBtn.setText("Saving...");

        Thread.ofVirtual().start(() -> {
            try {
                byte[] key = SessionService.getInstance().getVaultKey();
                String userId = SessionService.getInstance().getUserId();
                VaultService vault = VaultService.getInstance();

                if (isEditing && editingEntry != null) {
                    vault.updateEntry(editingEntry.id(), userId, key, title,
                        username.isEmpty() ? null : username,
                        url.isEmpty() ? null : url,
                        category, favorite, password, notes);
                } else {
                    vault.createEntry(userId, key, title,
                        username.isEmpty() ? null : username,
                        url.isEmpty() ? null : url,
                        category, favorite, password, notes);
                }

                Platform.runLater(() -> {
                    if (onSave != null) onSave.run();
                    closeDialog();
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    showError("Save failed: " + e.getMessage());
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
        Stage stage = (Stage) saveBtn.getScene().getWindow();
        stage.close();
    }

    private void showError(String msg) {
        Platform.runLater(() -> {
            errorLabel.setText(msg);
            errorLabel.setVisible(true);
        });
    }

    private void updateStrengthMeter(String password) {
        if (strengthRow == null) return;
        if (password.isEmpty()) {
            strengthRow.setVisible(false);
            return;
        }
        strengthRow.setVisible(true);
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
