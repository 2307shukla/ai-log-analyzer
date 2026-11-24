package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingDetectorTest {

    private final FindingDetector detector = new FindingDetector();

    private static LogEvent web(String ip, String path, int status) {
        return new LogEvent(ip, "GET", path, status, "Mozilla/5.0", false, "raw");
    }

    private static LogEvent webAgent(String ip, String agent) {
        return new LogEvent(ip, "GET", "/", 200, agent, false, "raw");
    }

    private static LogEvent fail(String ip, String user) {
        return new LogEvent(ip, null, null, null, null, true,
                "Failed password for " + user + " from " + ip, null, user);
    }

    private static LogEvent accepted(String ip, String user) {
        return new LogEvent(ip, null, null, null, null, false,
                "Accepted password for " + user + " from " + ip, null, user);
    }

    private static LogEvent at(String time, String ip) {
        return new LogEvent(ip, "GET", "/", 200, "Mozilla/5.0", false, "raw",
                Instant.parse(time), null);
    }

    private Optional<Finding> find(List<LogEvent> events, String rule) {
        return detector.detect(events).stream().filter(f -> f.rule().equals(rule)).findFirst();
    }

    private static List<LogEvent> repeat(int times, java.util.function.IntFunction<LogEvent> make) {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < times; i++) {
            events.add(make.apply(i));
        }
        return events;
    }

    @Test
    void cleanTrafficHasNoFindings() {
        List<LogEvent> events = repeat(20, i -> web("198.51.100." + (i % 5), "/page" + i, 200));

        assertTrue(detector.detect(events).isEmpty());
        assertEquals(0, FindingDetector.riskScore(detector.detect(events)));
        assertEquals("CLEAN", FindingDetector.riskLevel(detector.detect(events)));
    }

    @Test
    void bruteForceSeverityGrowsWithTheNumberOfFailures() {
        assertEquals(Severity.MEDIUM, find(repeat(3, i -> fail("203.0.113.5", "root")), "BRUTE_FORCE").get().severity());
        assertEquals(Severity.HIGH, find(repeat(10, i -> fail("203.0.113.5", "root")), "BRUTE_FORCE").get().severity());
        assertEquals(Severity.CRITICAL, find(repeat(50, i -> fail("203.0.113.5", "root")), "BRUTE_FORCE").get().severity());
        assertTrue(find(repeat(2, i -> fail("203.0.113.5", "root")), "BRUTE_FORCE").isEmpty());
    }

    @Test
    void passwordSprayingNeedsManyDifferentAccountsFromOneAddress() {
        List<LogEvent> five = repeat(5, i -> fail("203.0.113.5", "user" + i));
        List<LogEvent> four = repeat(4, i -> fail("203.0.113.5", "user" + i));

        assertEquals(Severity.HIGH, find(five, "PASSWORD_SPRAYING").get().severity());
        assertTrue(find(four, "PASSWORD_SPRAYING").isEmpty());
    }

    @Test
    void loginThatSucceedsAfterRepeatedFailuresIsCritical() {
        List<LogEvent> events = new ArrayList<>(repeat(4, i -> fail("203.0.113.5", "admin")));
        events.add(accepted("203.0.113.5", "admin"));

        Finding finding = find(events, "COMPROMISED_LOGIN").get();

        assertEquals(Severity.CRITICAL, finding.severity());
        assertEquals("T1078 Valid Accounts", finding.mitre());
        assertEquals("CRITICAL", FindingDetector.riskLevel(detector.detect(events)));
    }

    @Test
    void successBeforeFailuresOrFromAnotherAddressIsNotFlagged() {
        List<LogEvent> before = new ArrayList<>();
        before.add(accepted("203.0.113.5", "admin"));
        before.addAll(repeat(4, i -> fail("203.0.113.5", "admin")));
        assertTrue(find(before, "COMPROMISED_LOGIN").isEmpty());

        List<LogEvent> other = new ArrayList<>(repeat(4, i -> fail("203.0.113.5", "admin")));
        other.add(accepted("192.168.1.31", "deploy"));
        assertTrue(find(other, "COMPROMISED_LOGIN").isEmpty());
    }

    @Test
    void detectsSqlInjectionEvenWhenUrlEncoded() {
        List<LogEvent> events = List.of(web("203.0.113.45", "/product?id=1%27%20OR%201=1", 500));
        assertTrue(find(events, "SQL_INJECTION").isPresent());
        assertTrue(find(List.of(web("203.0.113.45", "/products?id=5", 200)), "SQL_INJECTION").isEmpty());
    }

    @Test
    void detectsScriptInjectionAndPathTraversal() {
        assertTrue(find(List.of(web("1.1.1.1", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)), "XSS").isPresent());
        assertTrue(find(List.of(web("1.1.1.1", "/files/../../etc/passwd", 400)), "PATH_TRAVERSAL").isPresent());
    }

    @Test
    void flagsKnownScannerUserAgents() {
        Finding finding = find(List.of(webAgent("192.0.2.66", "sqlmap/1.7.2#stable")), "SCANNER_USER_AGENT").get();
        assertEquals("T1595.002 Active Scanning: Vulnerability Scanning", finding.mitre());
        assertTrue(find(List.of(webAgent("1.1.1.1", "Mozilla/5.0")), "SCANNER_USER_AGENT").isEmpty());
    }

    @Test
    void sensitivePathProbingBecomesHighWhenOneAddressKeepsTrying() {
        assertEquals(Severity.MEDIUM, find(List.of(web("1.1.1.1", "/.env", 404)), "SENSITIVE_PATH_PROBING").get().severity());
        List<LogEvent> many = repeat(10, i -> web("1.1.1.1", "/.git/file" + i, 404));
        assertEquals(Severity.HIGH, find(many, "SENSITIVE_PATH_PROBING").get().severity());
    }

    @Test
    void forcedBrowsingNeedsTenDifferentMissingPages() {
        assertTrue(find(repeat(10, i -> web("1.1.1.1", "/missing" + i, 404)), "FORCED_BROWSING").isPresent());
        assertTrue(find(repeat(9, i -> web("1.1.1.1", "/missing" + i, 404)), "FORCED_BROWSING").isEmpty());
    }

    @Test
    void serverErrorClustersScaleWithTheirSize() {
        assertTrue(find(repeat(2, i -> web("1.1.1." + i, "/a", 500)), "SERVER_ERRORS").isEmpty());
        assertEquals(Severity.MEDIUM, find(repeat(3, i -> web("1.1.1." + i, "/a", 500)), "SERVER_ERRORS").get().severity());
        assertEquals(Severity.HIGH, find(repeat(20, i -> web("1.1.1." + i, "/a", 500)), "SERVER_ERRORS").get().severity());
    }

    @Test
    void detectsARequestBurstAgainstTheTypicalRate() {
        List<LogEvent> events = new ArrayList<>();
        for (int minute = 0; minute < 12; minute++) {
            String time = String.format("2026-11-12T08:%02d:10Z", minute);
            events.add(at(time, "10.0.0.1"));
            events.add(at(time, "10.0.0.2"));
        }
        for (int i = 0; i < 40; i++) {
            events.add(at("2026-11-12T08:30:" + String.format("%02d", i % 60) + "Z", "10.0.0." + (10 + i)));
        }

        assertTrue(find(events, "REQUEST_BURST").isPresent());
    }

    @Test
    void steadyTrafficIsNotABurst() {
        List<LogEvent> events = new ArrayList<>();
        for (int minute = 0; minute < 15; minute++) {
            for (int i = 0; i < 3; i++) {
                events.add(at(String.format("2026-11-12T08:%02d:%02dZ", minute, i * 10), "10.0.0." + i));
            }
        }
        assertTrue(find(events, "REQUEST_BURST").isEmpty());
    }

    @Test
    void riskScoreIsCappedAndASingleSeriousFindingIsNeverUnderstated() {
        Finding critical = new Finding("X", "t", Severity.CRITICAL, null, 1, "d", List.of(), "r");
        Finding high = new Finding("X", "t", Severity.HIGH, null, 1, "d", List.of(), "r");
        Finding low = new Finding("X", "t", Severity.LOW, null, 1, "d", List.of(), "r");

        assertEquals(100, FindingDetector.riskScore(List.of(critical, critical, critical)));
        assertEquals("CRITICAL", FindingDetector.riskLevel(List.of(critical)));
        assertEquals("HIGH", FindingDetector.riskLevel(List.of(high)));
        assertEquals("LOW", FindingDetector.riskLevel(List.of(low)));
    }

    @Test
    void findingsAreSortedMostSeriousFirst() {
        List<LogEvent> events = new ArrayList<>(repeat(3, i -> web("1.1.1." + i, "/a", 500)));
        events.addAll(repeat(4, i -> fail("203.0.113.5", "admin")));
        events.add(accepted("203.0.113.5", "admin"));

        List<Finding> findings = detector.detect(events);

        assertEquals(Severity.CRITICAL, findings.get(0).severity());
        for (int i = 1; i < findings.size(); i++) {
            assertTrue(findings.get(i - 1).severity().ordinal() <= findings.get(i).severity().ordinal());
        }
    }

    @Test
    void evidenceIsShortAndPrintableBecauseItComesFromUntrustedText() {
        String hostile = "/a'" + "x".repeat(500) + "\u0007bell";
        Finding finding = find(List.of(web("1.1.1.1", hostile, 500)), "SQL_INJECTION").get();

        for (String line : finding.evidence()) {
            assertTrue(line.length() <= 125, "evidence too long: " + line.length());
            assertFalse(line.chars().anyMatch(c -> c < 32 || c == 127), "control character in evidence");
        }
    }
}
