package com.passwordmanager.services;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-memory analysis of password hygiene. It receives decrypted passwords, so
 * it must never persist or log them.
 *
 * A password is:
 * - weak: shorter than 12 characters, or scored 0-1 by CryptoService
 * - reused: byte-for-byte identical to another entry's password
 * - stale: not updated for more than 180 days
 */
public final class SecurityAuditService {

    public static final int STALE_AFTER_DAYS = 180;

    private SecurityAuditService() {}

    public record Input(String title, String password, LocalDateTime updatedAt) {}

    public record Report(
        int total,
        int weak,
        int reused,
        int reusedGroups,
        int stale,
        int healthy,
        int score,
        int oldestDays,
        List<String> weakTitles,
        List<String> reusedTitles,
        List<String> staleTitles
    ) {}

    public static Report audit(List<Input> inputs, LocalDate today) {
        int total = inputs.size();
        if (total == 0) {
            return new Report(0, 0, 0, 0, 0, 0, 100, 0,
                              List.of(), List.of(), List.of());
        }

        CryptoService crypto = CryptoService.getInstance();
        Map<String, Integer> passwordCounts = new HashMap<>();
        for (Input input : inputs) {
            if (input.password() != null) {
                passwordCounts.merge(input.password(), 1, Integer::sum);
            }
        }

        int weak = 0, reused = 0, stale = 0, healthy = 0, oldestDays = 0;
        List<String> weakTitles = new ArrayList<>();
        List<String> reusedTitles = new ArrayList<>();
        List<String> staleTitles = new ArrayList<>();

        for (Input input : inputs) {
            boolean isWeak = input.password() == null
                || input.password().length() < 12
                || crypto.passwordStrength(input.password()) <= 1;
            boolean isReused = input.password() != null
                && passwordCounts.getOrDefault(input.password(), 0) > 1;
            int ageDays = input.updatedAt() == null ? 0
                : (int) ChronoUnit.DAYS.between(input.updatedAt().toLocalDate(), today);
            boolean isStale = ageDays > STALE_AFTER_DAYS;
            oldestDays = Math.max(oldestDays, Math.max(0, ageDays));

            if (isWeak) {
                weak++;
                weakTitles.add(input.title());
            }
            if (isReused) {
                reused++;
                reusedTitles.add(input.title());
            }
            if (isStale) {
                stale++;
                staleTitles.add(input.title());
            }
            if (!isWeak && !isReused && !isStale) {
                healthy++;
            }
        }

        int reusedGroups = 0;
        for (int count : passwordCounts.values()) {
            if (count > 1) reusedGroups++;
        }

        int score = (int) Math.round(healthy * 100.0 / total);
        return new Report(total, weak, reused, reusedGroups, stale, healthy, score, oldestDays,
                          List.copyOf(weakTitles), List.copyOf(reusedTitles), List.copyOf(staleTitles));
    }
}
