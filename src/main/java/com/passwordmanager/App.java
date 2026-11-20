package com.passwordmanager;

import com.passwordmanager.services.DatabaseService;
import com.passwordmanager.services.SessionService;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JavaFX Application entry point.
 * Initializes services and shows the first screen.
 */
public class App extends Application {

    private static final Logger LOG = Logger.getLogger(App.class.getName());
    private static final double LOGIN_WIDTH = 480;
    private static final double LOGIN_HEIGHT = 620;
    private static final double REGISTER_HEIGHT = 800;
    private static final double VAULT_WIDTH = 1100;
    private static final double VAULT_HEIGHT = 680;

    private static Stage primaryStage;
    private static String lastUsername = "";

    @Override
    public void start(Stage stage) throws Exception {
        primaryStage = stage;

        // Initialize database (creates file + schema if not exists)
        DatabaseService.getInstance().initialize();

        // Load first screen based on whether any user exists
        boolean hasUser = DatabaseService.getInstance().hasAnyUser();
        String fxml = hasUser ? "/com/passwordmanager/fxml/login.fxml"
                               : "/com/passwordmanager/fxml/register.fxml";
        double initialHeight = hasUser ? LOGIN_HEIGHT : REGISTER_HEIGHT;

        Scene scene = loadScene(fxml, LOGIN_WIDTH, initialHeight);
        applyTheme(scene);

        stage.setTitle("Vault — Password Manager");
        stage.setResizable(true);
        stage.setMinWidth(LOGIN_WIDTH);
        stage.setMinHeight(initialHeight);
        stage.setScene(scene);

        // App icon
        try {
            stage.getIcons().add(new Image(
                Objects.requireNonNull(getClass().getResourceAsStream("/com/passwordmanager/icons/icon.png"))
            ));
        } catch (Exception e) {
            LOG.warning("Could not load app icon: " + e.getMessage());
        }

        stage.show();
    }

    @Override
    public void stop() {
        SessionService.getInstance().destroy();
        DatabaseService.getInstance().close();
        Platform.exit();
    }

    // ─── Static helpers for controllers ──────────────────────────────────────

    /** Navigate to the login screen. */
    public static void showLogin() {
        Platform.runLater(() -> navigate(
            "/com/passwordmanager/fxml/login.fxml",
            "Vault — Password Manager",
            LOGIN_WIDTH, LOGIN_HEIGHT,
            LOGIN_WIDTH, LOGIN_HEIGHT
        ));
    }

    /** Navigate to the vault dashboard. */
    public static void showVault() {
        Platform.runLater(() -> navigate(
            "/com/passwordmanager/fxml/vault.fxml",
            "Vault — Password Manager",
            VAULT_WIDTH, VAULT_HEIGHT,
            900, 600
        ));
    }

    /** Navigate to the register screen. */
    public static void showRegister() {
        Platform.runLater(() -> navigate(
            "/com/passwordmanager/fxml/register.fxml",
            "Vault — Create Account",
            LOGIN_WIDTH, REGISTER_HEIGHT,
            LOGIN_WIDTH, REGISTER_HEIGHT
        ));
    }

    public static Stage getPrimaryStage() {
        return primaryStage;
    }

    /** Hide any modal dialogs owned by the main window (for example on lock). */
    public static void closeOwnedWindows() {
        if (primaryStage == null) return;
        for (Window window : Window.getWindows()) {
            if (window instanceof Stage stage
                && stage != primaryStage
                && stage.getOwner() == primaryStage) {
                stage.hide();
            }
        }
    }

    public static void setLastUsername(String username) {
        lastUsername = username == null ? "" : username;
    }

    public static String getLastUsername() {
        return lastUsername;
    }

    private static void navigate(String fxmlPath, String title,
                                 double width, double height,
                                 double minWidth, double minHeight) {
        try {
            // Never leave a modal dialog (with a decrypted password in it) on screen.
            closeOwnedWindows();

            Scene scene = loadScene(fxmlPath, width, height);
            applyTheme(scene);
            primaryStage.setTitle(title);
            primaryStage.setScene(scene);
            primaryStage.setMinWidth(minWidth);
            primaryStage.setMinHeight(minHeight);
            primaryStage.setWidth(width);
            primaryStage.setHeight(height);
            primaryStage.centerOnScreen();
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Failed to load screen: " + fxmlPath, e);
        }
    }

    private static Scene loadScene(String fxmlPath, double width, double height) throws Exception {
        FXMLLoader loader = new FXMLLoader(App.class.getResource(fxmlPath));
        return new Scene(loader.load(), width, height);
    }

    private static void applyTheme(Scene scene) {
        scene.getStylesheets().add(
            Objects.requireNonNull(App.class.getResource("/com/passwordmanager/css/app.css")).toExternalForm()
        );
    }

    public static void main(String[] args) {
        launch(args);
    }
}
