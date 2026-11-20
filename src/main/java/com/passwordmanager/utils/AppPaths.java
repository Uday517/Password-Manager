package com.passwordmanager.utils;

import java.nio.file.Path;

/**
 * Platform-aware application data paths.
 * Follows OS conventions for application data storage.
 *
 * The {@code vault.data.dir} system property overrides the location. This is
 * used by the test suite and by anyone who wants a portable vault (for example
 * on a USB stick).
 */
public final class AppPaths {

    public static final String DATA_DIR_PROPERTY = "vault.data.dir";
    private static final String APP_NAME = "VaultPasswordManager";

    private AppPaths() {}

    /** Directory that contains {@code vault.db} and its SQLite side files. */
    public static Path getDataDir() {
        String override = System.getProperty(DATA_DIR_PROPERTY);
        if (override != null && !override.isBlank()) {
            return Path.of(override).toAbsolutePath().normalize();
        }

        String os = System.getProperty("os.name", "").toLowerCase();
        String home = System.getProperty("user.home");

        if (os.contains("win")) {
            String appData = System.getenv("APPDATA");
            return Path.of(appData != null ? appData : home, APP_NAME);
        }
        if (os.contains("mac")) {
            return Path.of(home, "Library", "Application Support", APP_NAME);
        }
        // Linux / FreeBSD / other POSIX
        String xdgData = System.getenv("XDG_DATA_HOME");
        if (xdgData != null && !xdgData.isBlank()) {
            return Path.of(xdgData, APP_NAME);
        }
        return Path.of(home, ".local", "share", APP_NAME);
    }

    public static Path getDatabasePath() {
        return getDataDir().resolve("vault.db");
    }
}
