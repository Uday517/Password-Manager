package com.passwordmanager.models;

public record GeneratorOptions(
    int length,
    boolean useUppercase,
    boolean useLowercase,
    boolean useDigits,
    boolean useSpecial
) {
    public static GeneratorOptions defaults() {
        return new GeneratorOptions(20, true, true, true, true);
    }
}
