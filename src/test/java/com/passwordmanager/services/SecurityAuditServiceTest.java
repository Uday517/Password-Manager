package com.passwordmanager.services;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityAuditServiceTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 6, 1);

    @Test
    void countsWeakReusedStaleAndHealthyEntries() {
        String reused = "Reused-Password-2026!";
        List<SecurityAuditService.Input> inputs = List.of(
            input("Strong", "Correct-Horse-Battery-Staple-9!", TODAY.minusDays(10)),
            input("Reused A", reused, TODAY.minusDays(20)),
            input("Reused B", reused, TODAY.minusDays(30)),
            input("Weak", "abc123", TODAY.minusDays(5)),
            input("Stale", "Another-Str0ng-Password!", TODAY.minusDays(400)),
            input("Short", "Ab1!x", TODAY.minusDays(1))
        );

        SecurityAuditService.Report report = SecurityAuditService.audit(inputs, TODAY);

        assertEquals(6, report.total());
        assertEquals(2, report.weak());
        assertEquals(2, report.reused());
        assertEquals(1, report.reusedGroups());
        assertEquals(1, report.stale());
        assertEquals(1, report.healthy());
        assertEquals(17, report.score());
        assertEquals(400, report.oldestDays());
        assertEquals(1, report.healthy());
        assertTrue(report.weakTitles().contains("Weak"));
        assertTrue(report.reusedTitles().contains("Reused A"));
        assertTrue(report.staleTitles().contains("Stale"));
    }

    @Test
    void emptyVaultIsReportedAsPerfect() {
        SecurityAuditService.Report report = SecurityAuditService.audit(List.of(), TODAY);
        assertEquals(0, report.total());
        assertEquals(100, report.score());
        assertTrue(report.weakTitles().isEmpty());
    }

    @Test
    void staleThresholdIsExclusiveAtExactlyOneHundredEightyDays() {
        List<SecurityAuditService.Input> boundary = List.of(
            input("At boundary", "Correct-Horse-Battery-Staple-9!",
                TODAY.minusDays(SecurityAuditService.STALE_AFTER_DAYS)),
            input("Over boundary", "Another-Str0ng-Password-2026!",
                TODAY.minusDays(SecurityAuditService.STALE_AFTER_DAYS + 1))
        );

        SecurityAuditService.Report report = SecurityAuditService.audit(boundary, TODAY);
        assertEquals(1, report.stale());
        assertEquals(1, report.healthy());
    }

    private static SecurityAuditService.Input input(String title, String password, LocalDate updated) {
        return new SecurityAuditService.Input(title, password, updated.atStartOfDay());
    }
}
