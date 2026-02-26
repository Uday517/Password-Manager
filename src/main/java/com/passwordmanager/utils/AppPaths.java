package com.passwordmanager.utils;

import java.nio.file.Path;

/**
 * Platform-aware application data paths.
 * Follows OS conventions for application data storage.
 */
public final class AppPaths {

    private static final String APP_NAME = "VaultPasswordManager";

    private AppPaths() {}

    public static Path getDatabasePath() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String home = System.getProperty("user.home");

        Path dataDir;
        if (os.contains("win")) {
            String appData = System.getenv("APPDATA");
            dataDir = Path.of(appData != null ? appData : home, APP_NAME);
        } else if (os.contains("mac")) {
            dataDir = Path.of(home, "Library", "Application Support", APP_NAME);
        } else {
            // Linux / FreeBSD / other POSIX
            String xdgData = System.getenv("XDG_DATA_HOME");
            if (xdgData != null && !xdgData.isBlank()) {
                dataDir = Path.of(xdgData, APP_NAME);
            } else {
                dataDir = Path.of(home, ".local", "share", APP_NAME);
            }
        }
        return dataDir.resolve("vault.db");
    }
}
