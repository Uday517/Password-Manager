package com.passwordmanager.controllers;

import com.passwordmanager.App;
import com.passwordmanager.models.User;
import com.passwordmanager.services.CryptoService;
import com.passwordmanager.services.DatabaseService;
import com.passwordmanager.services.SessionService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.VBox;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;

public class LoginController {

    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 30;

    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private Button loginBtn;
    @FXML private Label errorLabel;
    @FXML private Label attemptsLabel;
    @FXML private Label lockoutLabel;
    @FXML private VBox lockoutBox;
    @FXML private Hyperlink createAccountLink;

    @FXML
    public void initialize() {
        errorLabel.setVisible(false);
        attemptsLabel.setVisible(false);
        lockoutBox.setVisible(false);

        // Allow pressing Enter to submit
        passwordField.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER) handleLogin();
        });
        usernameField.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER) passwordField.requestFocus();
        });
    }

    @FXML
    private void handleLogin() {
        String username = usernameField.getText().trim();
        char[] password = passwordField.getText().toCharArray();

        hideError();
        setLoading(true);

        // Run on background thread to avoid blocking the UI during PBKDF2
        Thread.ofVirtual().start(() -> {
            try {
                performLogin(username, password);
            } finally {
                Arrays.fill(password, '\0');
                Platform.runLater(() -> setLoading(false));
            }
        });
    }

    private void performLogin(String username, char[] password) {
        try {
            if (username.isBlank()) {
                showError("Username is required.");
                return;
            }

            Optional<User> userOpt = DatabaseService.getInstance().findUserByUsername(username);
            if (userOpt.isEmpty()) {
                // Generic error — don't reveal whether user exists (timing attack mitigation)
                showError("Invalid username or password.");
                return;
            }

            User user = userOpt.get();

            // Check lockout
            if (user.lockedUntil() != null && LocalDateTime.now().isBefore(user.lockedUntil())) {
                long minutes = java.time.Duration.between(LocalDateTime.now(), user.lockedUntil()).toMinutes() + 1;
                showLockout("Too many failed attempts. Try again in " + minutes + " minute" + (minutes == 1 ? "" : "s") + ".");
                return;
            }

            // Verify password
            boolean valid = CryptoService.getInstance().verifyMasterPassword(
                password, user.passwordSalt(), user.passwordHash()
            );

            if (!valid) {
                int newAttempts = user.failedAttempts() + 1;
                DatabaseService.getInstance().incrementFailedAttempts(user.id());

                if (newAttempts >= MAX_ATTEMPTS) {
                    DatabaseService.getInstance().lockUser(
                        user.id(), LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES)
                    );
                    showLockout("Account locked for " + LOCKOUT_MINUTES + " minutes after " + MAX_ATTEMPTS + " failed attempts.");
                } else {
                    int remaining = MAX_ATTEMPTS - newAttempts;
                    showError("Invalid username or password. " + remaining + " attempt" + (remaining == 1 ? "" : "s") + " remaining.");
                }
                return;
            }

            // Password correct — derive vault key and create session
            DatabaseService.getInstance().resetFailedAttempts(user.id());
            byte[] vaultKey = CryptoService.getInstance().deriveVaultKey(password, user.passwordSalt());

            SessionService.getInstance().create(user.id(), vaultKey, App::showLogin);
            Arrays.fill(vaultKey, (byte) 0);  // zero our copy; SessionService keeps its own

            App.showVault();

        } catch (Exception e) {
            showError("Login failed. Please try again.");
        }
    }

    @FXML
    private void handleCreateAccount() {
        App.showRegister();
    }

    private void showError(String msg) {
        Platform.runLater(() -> {
            errorLabel.setText(msg);
            errorLabel.setVisible(true);
            lockoutBox.setVisible(false);
        });
    }

    private void showLockout(String msg) {
        Platform.runLater(() -> {
            lockoutLabel.setText(msg);
            lockoutBox.setVisible(true);
            errorLabel.setVisible(false);
        });
    }

    private void hideError() {
        errorLabel.setVisible(false);
        lockoutBox.setVisible(false);
    }

    private void setLoading(boolean loading) {
        loginBtn.setDisable(loading);
        loginBtn.setText(loading ? "Verifying..." : "Unlock Vault");
        usernameField.setDisable(loading);
        passwordField.setDisable(loading);
    }
}
