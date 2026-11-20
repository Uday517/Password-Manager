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
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RegisterController {

    private static final Logger LOG = Logger.getLogger(RegisterController.class.getName());

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
        errorLabel.setManaged(false);
        strengthRow.setVisible(false);
        strengthRow.setManaged(false);

        passwordField.textProperty().addListener((obs, oldVal, newVal) ->
            updateStrengthMeter(newVal)
        );
        Platform.runLater(usernameField::requestFocus);
    }

    private void updateStrengthMeter(String password) {
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

    @FXML
    private void handleRegister() {
        String username = usernameField.getText().trim();
        char[] password = passwordField.getText().toCharArray();
        char[] confirm = confirmPasswordField.getText().toCharArray();

        hideError();

        if (!Arrays.equals(password, confirm)) {
            showError("Passwords do not match.");
            clearPasswords(password, confirm);
            return;
        }

        setLoading(true);

        final char[] pwdCopy = Arrays.copyOf(password, password.length);
        clearPasswords(password, confirm);

        Thread.ofVirtual().start(() -> {
            try {
                performRegistration(username, pwdCopy);
            } catch (AuthService.AuthException e) {
                showError(e.getMessage());
            } catch (Exception e) {
                LOG.log(Level.SEVERE, "Registration failed", e);
                showError("Registration failed. Please try again.");
            } finally {
                Arrays.fill(pwdCopy, '\0');
                Platform.runLater(() -> setLoading(false));
            }
        });
    }

    private void performRegistration(String username, char[] password) throws Exception {
        User user = AuthService.getInstance().register(username, password);

        byte[] vaultKey = CryptoService.getInstance()
            .deriveVaultKey(password, user.passwordSalt());
        try {
            SessionService.getInstance().create(
                user.id(), user.username(), vaultKey, App::showLogin);
            App.setLastUsername(user.username());
        } finally {
            Arrays.fill(vaultKey, (byte) 0);
        }

        App.showVault();
    }

    @FXML
    private void handleBackToLogin() {
        App.showLogin();
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
