package com.passwordmanager.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppPathsTest {

    private String previous;

    @BeforeEach
    void remember() {
        previous = System.getProperty(AppPaths.DATA_DIR_PROPERTY);
    }

    @AfterEach
    void restore() {
        if (previous == null) {
            System.clearProperty(AppPaths.DATA_DIR_PROPERTY);
        } else {
            System.setProperty(AppPaths.DATA_DIR_PROPERTY, previous);
        }
    }

    @Test
    void overrideWins() {
        Path custom = Path.of("/tmp/vault-test-custom").toAbsolutePath();
        System.setProperty(AppPaths.DATA_DIR_PROPERTY, custom.toString());

        assertEquals(custom, AppPaths.getDataDir());
        assertEquals(custom.resolve("vault.db"), AppPaths.getDatabasePath());
    }

    @Test
    void defaultPathIsPlatformAppropriate() {
        System.clearProperty(AppPaths.DATA_DIR_PROPERTY);

        Path database = AppPaths.getDatabasePath();
        assertEquals("vault.db", database.getFileName().toString());
        assertTrue(database.isAbsolute());
        assertTrue(database.toString().contains("VaultPasswordManager"));
    }
}
