package com.passwordmanager.controllers;

import com.passwordmanager.App;
import com.passwordmanager.models.User;
import com.passwordmanager.services.AuthService;
import com.passwordmanager.services.CryptoService;
import com.passwordmanager.services.SessionService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Hyperlink;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.VBox;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoginController {

    private static final Logger LOG = Logger.getLogger(LoginController.class.getName());

    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private Button loginBtn;
    @FXML private Label errorLabel;
    @FXML private Label lockoutLabel;
    @FXML private VBox lockoutBox;
    @FXML private Hyperlink createAccountLink;

    @FXML
    public void initialize() {
        errorLabel.setVisible(false);
        errorLabel.setManaged(false);
        lockoutBox.setVisible(false);
        lockoutBox.setManaged(false);

        String remembered = App.getLastUsername();
        if (!remembered.isBlank()) {
            usernameField.setText(remembered);
            Platform.runLater(passwordField::requestFocus);
        }

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

        // Run on a background thread to avoid blocking the UI during PBKDF2
        Thread.ofVirtual().start(() -> {
            try {
                performLogin(username, password);
            } catch (Exception e) {
                LOG.log(Level.SEVERE, "Login failed", e);
                showError("Login failed. Please try again.");
            } finally {
                Arrays.fill(password, '\0');
                Platform.runLater(() -> setLoading(false));
            }
        });
    }

    private void performLogin(String username, char[] password) throws Exception {
        AuthService.LoginResult result = AuthService.getInstance().authenticate(username, password);

        switch (result.status()) {
            case LOCKED -> showLockout("Account locked. Try again in "
                + result.lockoutMinutes() + " minute"
                + (result.lockoutMinutes() == 1 ? "" : "s") + ".");

            case INVALID_CREDENTIALS -> {
                if (result.remainingAttempts() >= 0) {
                    int remaining = result.remainingAttempts();
                    showError("Invalid username or password. " + remaining + " attempt"
                        + (remaining == 1 ? "" : "s") + " remaining.");
                } else {
                    showError("Invalid username or password.");
                }
            }

            case SUCCESS -> {
                User user = result.user();
                byte[] vaultKey = CryptoService.getInstance()
                    .deriveVaultKey(password, user.passwordSalt());
                try {
                    SessionService.getInstance().create(
                        user.id(), user.username(), vaultKey, App::showLogin);
                    App.setLastUsername(user.username());
                } finally {
                    Arrays.fill(vaultKey, (byte) 0);  // SessionService keeps its own copy
                }
                App.showVault();
            }
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
            errorLabel.setManaged(true);
            lockoutBox.setVisible(false);
            lockoutBox.setManaged(false);
        });
    }

    private void showLockout(String msg) {
        Platform.runLater(() -> {
            lockoutLabel.setText(msg);
            lockoutBox.setVisible(true);
            lockoutBox.setManaged(true);
            errorLabel.setVisible(false);
            errorLabel.setManaged(false);
        });
    }

    private void hideError() {
        errorLabel.setVisible(false);
        errorLabel.setManaged(false);
        lockoutBox.setVisible(false);
        lockoutBox.setManaged(false);
    }

    private void setLoading(boolean loading) {
        loginBtn.setDisable(loading);
        loginBtn.setText(loading ? "Verifying..." : "Unlock Vault");
        usernameField.setDisable(loading);
        passwordField.setDisable(loading);
    }
}
