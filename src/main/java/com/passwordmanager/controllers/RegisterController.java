package com.passwordmanager.controllers;

import com.passwordmanager.App;
import com.passwordmanager.services.CryptoService;
import com.passwordmanager.services.DatabaseService;
import com.passwordmanager.services.SessionService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;

import java.util.Arrays;
import java.util.UUID;

public class RegisterController {

    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private PasswordField confirmPasswordField;
    @FXML private Button registerBtn;
    @FXML private Label errorLabel;
    @FXML private Label strengthLabel;
    @FXML private Region strengthBar;
    @FXML private HBox strengthRow;
    @FXML private Hyperlink loginLink;

    @FXML
    public void initialize() {
        errorLabel.setVisible(false);
        strengthRow.setVisible(false);

        passwordField.textProperty().addListener((obs, oldVal, newVal) -> {
            updateStrengthMeter(newVal);
        });
    }

    private void updateStrengthMeter(String password) {
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

    @FXML
    private void handleRegister() {
        String username = usernameField.getText().trim();
        char[] password = passwordField.getText().toCharArray();
        char[] confirm = confirmPasswordField.getText().toCharArray();

        hideError();

        // Validation
        if (username.isBlank()) {
            showError("Username is required.");
            clearPasswords(password, confirm);
            return;
        }
        if (username.length() < 3 || username.length() > 50) {
            showError("Username must be between 3 and 50 characters.");
            clearPasswords(password, confirm);
            return;
        }
        if (!username.matches("[a-zA-Z0-9_.-]+")) {
            showError("Username may only contain letters, digits, underscores, dots and hyphens.");
            clearPasswords(password, confirm);
            return;
        }
        if (password.length < 8) {
            showError("Master password must be at least 8 characters.");
            clearPasswords(password, confirm);
            return;
        }
        if (!Arrays.equals(password, confirm)) {
            showError("Passwords do not match.");
            clearPasswords(password, confirm);
            return;
        }
        if (CryptoService.getInstance().passwordStrength(new String(password)) < 2) {
            showError("Master password is too weak. Use a mix of letters, numbers and symbols.");
            clearPasswords(password, confirm);
            return;
        }

        setLoading(true);

        final char[] pwdCopy = Arrays.copyOf(password, password.length);
        clearPasswords(password, confirm);

        Thread.ofVirtual().start(() -> {
            try {
                performRegistration(username, pwdCopy);
            } finally {
                Arrays.fill(pwdCopy, '\0');
                Platform.runLater(() -> setLoading(false));
            }
        });
    }

    private void performRegistration(String username, char[] password) {
        try {
            // Check username uniqueness
            if (DatabaseService.getInstance().findUserByUsername(username).isPresent()) {
                showError("Username already taken. Please choose another.");
                return;
            }

            // Hash master password
            String[] hashResult = CryptoService.getInstance().hashMasterPassword(password);
            String salt = hashResult[0];
            String hash = hashResult[1];

            // Derive vault key for the new session
            byte[] vaultKey = CryptoService.getInstance().deriveVaultKey(password, salt);

            // Persist user
            String userId = UUID.randomUUID().toString();
            DatabaseService.getInstance().createUser(userId, username, hash, salt);

            // Create session and go to vault
            SessionService.getInstance().create(userId, vaultKey, App::showLogin);
            Arrays.fill(vaultKey, (byte) 0);

            App.showVault();

        } catch (Exception e) {
            showError("Registration failed: " + e.getMessage());
        }
    }

    @FXML
    private void handleBackToLogin() {
        App.showLogin();
    }

    private void showError(String msg) {
        Platform.runLater(() -> {
            errorLabel.setText(msg);
            errorLabel.setVisible(true);
        });
    }

    private void hideError() {
        errorLabel.setVisible(false);
    }

    private void setLoading(boolean loading) {
        registerBtn.setDisable(loading);
        registerBtn.setText(loading ? "Creating account..." : "Create Account");
        usernameField.setDisable(loading);
        passwordField.setDisable(loading);
        confirmPasswordField.setDisable(loading);
    }

    private void clearPasswords(char[]... arrays) {
        for (char[] arr : arrays) Arrays.fill(arr, '\0');
    }
}
