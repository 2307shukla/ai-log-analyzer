package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import com.abhijeet.loganalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformRulesTest {

    private final FindingDetector detector = new FindingDetector();

    private static LogEvent event(LogFormat format, String ip, String user, String category, String detail,
                                  Integer port, String level, Instant time, boolean failure) {
        return new LogEvent(ip, null, null, null, null, failure, "raw", time, user, format, level,
                category, detail, port);
    }

    private static LogEvent windows(String category, String id, String user, String ip) {
        return event(LogFormat.WINDOWS_EVENT, ip, user, category, id, null, null, null,
                "logon_failure".equals(category));
    }

    private static LogEvent trail(String category, String name, String user) {
        return event(LogFormat.CLOUDTRAIL, "203.0.113.200", user, category, name, null, null, null,
                "console_login_failure".equals(category));
    }

    private Optional<Finding> find(List<LogEvent> events, String rule) {
        return detector.detect(events).stream().filter(f -> f.rule().equals(rule)).findFirst();
    }

    @Test
    void windowsAuditLogClearedIsCritical() {
        Finding f = find(List.of(windows("audit_log_cleared", "1102", "helpdesk2", null)), "AUDIT_LOG_CLEARED").get();
        assertEquals(Severity.CRITICAL, f.severity());
        assertEquals("T1070.001 Indicator Removal: Clear Windows Event Logs", f.mitre());
    }

    @Test
    void windowsAccountAndGroupChanges() {
        assertEquals(Severity.MEDIUM, find(List.of(windows("account_created", "4720", "x", null)), "ACCOUNT_CREATED").get().severity());
        assertEquals(Severity.HIGH, find(List.of(windows("added_to_group", "4732", "x", null)), "PRIVILEGED_GROUP_CHANGE").get().severity());
        assertTrue(find(List.of(windows("account_lockout", "4740", "x", null)), "ACCOUNT_LOCKOUT").isPresent());
        Finding privilege = find(List.of(windows("special_privileges", "4672", "admin1", null)), "PRIVILEGE_USE").get();
        assertEquals(Severity.LOW, privilege.severity());
        assertTrue(privilege.evidence().get(0).startsWith("admin1"));
    }

    @Test
    void windowsFailedThenSuccessfulLogonIsACompromisedLogin() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            events.add(windows("logon_failure", "4625", "svc_sql", "203.0.113.77"));
        }
        events.add(windows("logon_success", "4624", "svc_sql", "203.0.113.77"));

        assertTrue(find(events, "BRUTE_FORCE").isPresent());
        assertEquals(Severity.CRITICAL, find(events, "COMPROMISED_LOGIN").get().severity());
    }

    @Test
    void cloudTrailRules() {
        assertEquals(Severity.CRITICAL, find(List.of(trail("logging_disabled", "StopLogging", "alice")),
                "CLOUD_LOGGING_DISABLED").get().severity());
        assertEquals(Severity.HIGH, find(List.of(trail("console_login_no_mfa", "ConsoleLogin", "alice")),
                "CONSOLE_LOGIN_WITHOUT_MFA").get().severity());
        assertEquals(Severity.MEDIUM, find(List.of(trail("iam_change", "DeleteUser", "alice")),
                "IAM_CHANGES").get().severity());
        assertEquals(Severity.HIGH, find(List.of(trail("iam_change", "AttachUserPolicy", "alice")),
                "IAM_CHANGES").get().severity());
    }

    @Test
    void rootUsageIsHighAndCriticalWithAConsoleSignIn() {
        assertEquals(Severity.HIGH, find(List.of(trail(null, "ListBuckets", "root")), "ROOT_ACCOUNT_USAGE").get().severity());
        assertEquals(Severity.CRITICAL, find(List.of(trail("console_login", "ConsoleLogin", "root")),
                "ROOT_ACCOUNT_USAGE").get().severity());
        assertTrue(find(List.of(trail(null, "ListBuckets", "alice")), "ROOT_ACCOUNT_USAGE").isEmpty());
    }

    @Test
    void portScanNeedsTenDistinctPorts() {
        List<LogEvent> ten = new ArrayList<>();
        List<LogEvent> nine = new ArrayList<>();
        for (int p = 1; p <= 10; p++) {
            ten.add(event(LogFormat.FIREWALL, "203.0.113.150", null, "firewall_block", "192.0.2.20", p, null, null, false));
            if (p < 10) {
                nine.add(ten.get(ten.size() - 1));
            }
        }
        assertEquals("T1046 Network Service Discovery", find(ten, "PORT_SCAN").get().mitre());
        assertTrue(find(nine, "PORT_SCAN").isEmpty());
        assertTrue(find(ten, "TRAFFIC_CONCENTRATION").isEmpty(), "firewall events are not web requests");
    }

    @Test
    void firewallBlockVolume() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            events.add(event(LogFormat.FIREWALL, "198.51.100." + (i % 4), null, "firewall_block", "d", 22, null, null, false));
        }
        assertEquals(Severity.LOW, find(events, "FIREWALL_BLOCKS").get().severity());
        assertTrue(find(events.subList(0, 19), "FIREWALL_BLOCKS").isEmpty());
    }

    @Test
    void applicationExceptionsAreGroupedByClassWithRootCauses() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            events.add(event(LogFormat.SPRING_BOOT, null, null, "exception", "java.lang.NullPointerException", null, null, null, false));
            events.add(event(LogFormat.SPRING_BOOT, null, null, "caused_by", "java.sql.SQLException", null, null, null, false));
        }
        Finding f = find(events, "APP_EXCEPTIONS").get();
        assertEquals(3, f.count());
        assertTrue(f.evidence().contains("java.lang.NullPointerException x3"));
        assertTrue(f.evidence().contains("root cause: java.sql.SQLException x3"));
        assertTrue(find(events.subList(0, 4), "APP_EXCEPTIONS").isEmpty());
    }

    @Test
    void errorBurstIsMeasuredAgainstTheUsualErrorRate() {
        List<LogEvent> events = new ArrayList<>();
        for (int m = 0; m < 5; m++) {
            events.add(event(LogFormat.SPRING_BOOT, null, null, "app_error", null, null, "ERROR",
                    Instant.parse(String.format("2026-11-12T09:%02d:00Z", m)), false));
        }
        for (int i = 0; i < 12; i++) {
            events.add(event(LogFormat.SPRING_BOOT, null, null, "app_error", null, null, "ERROR",
                    Instant.parse(String.format("2026-11-12T09:30:%02dZ", i)), false));
            // Stack frames carry no level, so they never inflate the count.
            events.add(event(LogFormat.SPRING_BOOT, null, null, "stack_frame", null, null, null,
                    Instant.parse(String.format("2026-11-12T09:30:%02dZ", i)), false));
        }
        Finding f = find(events, "ERROR_BURST").get();
        assertEquals(12, f.count());

        List<LogEvent> steady = new ArrayList<>();
        for (int m = 0; m < 10; m++) {
            for (int i = 0; i < 12; i++) {
                steady.add(event(LogFormat.SPRING_BOOT, null, null, "app_error", null, null, "ERROR",
                        Instant.parse(String.format("2026-11-12T09:%02d:%02dZ", m, i)), false));
            }
        }
        assertTrue(find(steady, "ERROR_BURST").isEmpty());
    }

    @Test
    void containerRules() {
        LogEvent crash = event(LogFormat.CONTAINER, null, null, "crash_loop", "payments", null, null, null, false);
        assertEquals(Severity.HIGH, find(List.of(crash), "CRASH_LOOP").get().severity());
        List<LogEvent> three = List.of(crash,
                event(LogFormat.CONTAINER, null, null, "crash_loop", "orders", null, null, null, false),
                event(LogFormat.CONTAINER, null, null, "crash_loop", "search", null, null, null, false));
        assertEquals(Severity.CRITICAL, find(three, "CRASH_LOOP").get().severity());

        assertTrue(find(List.of(event(LogFormat.CONTAINER, null, null, "oom_kill", "java", null, null, null, false)),
                "OOM_KILL").isPresent());
        LogEvent probe = event(LogFormat.CONTAINER, null, null, "probe_failed", "p", null, null, null, false);
        assertTrue(find(List.of(probe, probe), "PROBE_FAILURES").isEmpty());
        assertTrue(find(List.of(probe, probe, probe), "PROBE_FAILURES").isPresent());
        assertTrue(find(List.of(event(LogFormat.CONTAINER, null, null, "image_pull_error", "s", null, null, null, false)),
                "IMAGE_PULL_ERRORS").isPresent());
    }

    private static LogEvent web(String ip, String method, String path, int status) {
        return new LogEvent(ip, method, path, status, "ua", false, "raw");
    }

    @Test
    void webLoginBruteForceNeedsTenLoginRequestsFromOneAddress() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(web("198.51.100.201", "POST", "/wp-login.php", 401));
        }
        Finding f = find(events, "WEB_LOGIN_BRUTE_FORCE").get();
        assertEquals("T1110.001 Brute Force: Password Guessing", f.mitre());
        assertTrue(find(events.subList(0, 9), "WEB_LOGIN_BRUTE_FORCE").isEmpty());

        List<LogEvent> pages = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            pages.add(web("192.0.2.1", "GET", "/login", 200));
        }
        assertTrue(find(pages, "WEB_LOGIN_BRUTE_FORCE").isEmpty(), "viewing the login page is not an attempt");
    }

    @Test
    void sshRootLoginAttemptsAndSuccess() {
        LogEvent fail = new LogEvent("203.0.113.5", null, null, null, null, true,
                "Failed password for root from 203.0.113.5", null, "root", LogFormat.SSH, null, "logon_failure", null, null);
        LogEvent ok = new LogEvent("203.0.113.5", null, null, null, null, false,
                "Accepted password for root from 203.0.113.5", null, "root", LogFormat.SSH, null, "logon_success", null, null);

        assertEquals(Severity.MEDIUM, find(List.of(fail), "SSH_ROOT_LOGIN").get().severity());
        Finding success = find(List.of(fail, ok), "SSH_ROOT_LOGIN").get();
        assertEquals(Severity.HIGH, success.severity());
        assertEquals("Root logged in over SSH", success.title());
    }

    private static LogEvent linux(String category, String user, String detail) {
        return event(LogFormat.SYSLOG, null, user, category, detail, null, null, null, category.endsWith("failure"));
    }

    @Test
    void sudoAndSuUsageIsMediumWhenItOpensAShell() {
        assertEquals(Severity.LOW, find(List.of(linux("sudo_command", "alice", "/usr/bin/apt update")),
                "SUDO_SU_USAGE").get().severity());
        Finding shell = find(List.of(linux("sudo_command", "alice", "/usr/bin/apt update"),
                linux("sudo_command", "bob", "/bin/bash")), "SUDO_SU_USAGE").get();
        assertEquals(Severity.MEDIUM, shell.severity());
        assertTrue(shell.evidence().get(0).startsWith("bob ran /bin/bash"), "risky commands are listed first");
        assertEquals(Severity.MEDIUM, find(List.of(linux("su_session", "bob", "root")), "SUDO_SU_USAGE").get().severity());
    }

    @Test
    void repeatedSudoFailures() {
        List<LogEvent> failures = List.of(linux("sudo_failure", "www-data", null), linux("su_failure", "www-data", null),
                linux("sudo_failure", "www-data", null));
        assertTrue(find(failures, "SUDO_SU_FAILURES").isPresent());
        assertTrue(find(failures.subList(0, 2), "SUDO_SU_FAILURES").isEmpty());
    }

    @Test
    void linuxAccountAndGroupChangesShareTheWindowsRules() {
        assertTrue(find(List.of(linux("account_created", "sysupdate", null)), "ACCOUNT_CREATED").isPresent());
        Finding group = find(List.of(linux("added_to_group", "sysupdate", "sudo")), "PRIVILEGED_GROUP_CHANGE").get();
        assertTrue(group.evidence().get(0).startsWith("sysupdate added to group sudo"));
    }

    @Test
    void cloudDeletionsAreHighWhenTheyDestroyData() {
        assertEquals(Severity.MEDIUM, find(List.of(trail("resource_deleted", "DeleteTags", "alice")),
                "DELETED_RESOURCES").get().severity());
        Finding f = find(List.of(trail("resource_deleted", "DeleteBucket", "alice")), "DELETED_RESOURCES").get();
        assertEquals(Severity.HIGH, f.severity());
        assertEquals("T1485 Data Destruction", f.mitre());
    }
}
