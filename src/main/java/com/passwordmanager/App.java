package com.passwordmanager;

import com.passwordmanager.services.DatabaseService;
import com.passwordmanager.services.SessionService;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * JavaFX Application entry point.
 * Initializes services and shows the first screen.
 */
public class App extends Application {

    private static final Logger LOG = Logger.getLogger(App.class.getName());
    private static Stage primaryStage;

    @Override
    public void start(Stage stage) throws Exception {
        primaryStage = stage;

        // Initialize database (creates file + schema if not exists)
        DatabaseService.getInstance().initialize();

        // Load first screen based on whether any user exists
        boolean hasUser = DatabaseService.getInstance().hasAnyUser();
        String fxml = hasUser ? "/com/passwordmanager/fxml/login.fxml"
                               : "/com/passwordmanager/fxml/register.fxml";

        Scene scene = loadScene(fxml, 480, 580);
        applyTheme(scene);

        stage.setTitle("Vault — Password Manager");
        stage.setResizable(true);
        stage.setMinWidth(480);
        stage.setMinHeight(520);
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
        Platform.runLater(() -> {
            try {
                Scene scene = loadScene("/com/passwordmanager/fxml/login.fxml", 480, 580);
                applyTheme(scene);
                primaryStage.setScene(scene);
                primaryStage.setWidth(480);
                primaryStage.setHeight(580);
                primaryStage.centerOnScreen();
            } catch (Exception e) {
                LOG.severe("Failed to load login screen: " + e.getMessage());
            }
        });
    }

    /** Navigate to the vault dashboard. */
    public static void showVault() {
        Platform.runLater(() -> {
            try {
                Scene scene = loadScene("/com/passwordmanager/fxml/vault.fxml", 1100, 680);
                applyTheme(scene);
                primaryStage.setScene(scene);
                primaryStage.setMinWidth(900);
                primaryStage.setMinHeight(600);
                primaryStage.setWidth(1100);
                primaryStage.setHeight(680);
                primaryStage.centerOnScreen();
            } catch (Exception e) {
                LOG.severe("Failed to load vault screen: " + e.getMessage());
            }
        });
    }

    /** Navigate to the register screen. */
    public static void showRegister() {
        Platform.runLater(() -> {
            try {
                Scene scene = loadScene("/com/passwordmanager/fxml/register.fxml", 480, 640);
                applyTheme(scene);
                primaryStage.setScene(scene);
                primaryStage.setWidth(480);
                primaryStage.setHeight(640);
                primaryStage.centerOnScreen();
            } catch (Exception e) {
                LOG.severe("Failed to load register screen: " + e.getMessage());
            }
        });
    }

    public static Stage getPrimaryStage() {
        return primaryStage;
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
