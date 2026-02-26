package com.passwordmanager;

/**
 * Application entry point (not extending Application).
 *
 * This separate launcher class is required because JavaFX applications packaged
 * into an uber-JAR cannot have the main class extend Application directly —
 * the class loader won't find the JavaFX toolkit. Launching from a plain class
 * avoids this restriction.
 */
public class Launcher {
    public static void main(String[] args) {
        App.main(args);
    }
}
