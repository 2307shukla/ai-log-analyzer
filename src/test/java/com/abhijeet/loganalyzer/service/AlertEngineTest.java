package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Alert;
import com.abhijeet.loganalyzer.model.AlertRule;
import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import com.abhijeet.loganalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertEngineTest {

    /** The example from the brief: more than 5 failed logins from one IP in 1 minute. */
    private static final AlertRule BURST = new AlertRule("brute-force-burst",
            "More than 5 failed logins from one IP in 1 minute", "failed_logins", "ip", 5, "gt", 1,
            Severity.HIGH, null);

    private static LogEvent fail(String ip, String time) {
        return new LogEvent(ip, null, null, null, null, true, "raw", time == null ? null : Instant.parse(time), "root",
                LogFormat.SSH, null, "logon_failure", null, null);
    }

    private static List<LogEvent> failures(String ip, int count, int secondsApart) {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            events.add(fail(ip, Instant.parse("2026-11-12T03:20:00Z").plusSeconds((long) i * secondsApart).toString()));
        }
        return events;
    }

    private static List<Alert> run(List<LogEvent> events, AlertRule... rules) {
        return AlertEngine.evaluate(events, List.of(), 0, List.of(rules));
    }

    @Test
    void sixFailuresInsideOneMinuteFire() {
        List<Alert> alerts = run(failures("203.0.113.5", 6, 5), BURST);

        assertEquals(1, alerts.size());
        Alert a = alerts.get(0);
        assertEquals("203.0.113.5", a.group());
        assertEquals(6, a.value());
        assertEquals("2026-11-12T03:20:00Z", a.windowStart());
        assertTrue(a.message().startsWith("6 failed logins from 203.0.113.5 within 1 minute"), a.message());
    }

    @Test
    void exactlyFiveOrSpreadOutFailuresDoNotFire() {
        assertTrue(run(failures("203.0.113.5", 5, 5), BURST).isEmpty(), "more than 5 means 6 or more");
        assertTrue(run(failures("203.0.113.5", 12, 15), BURST).isEmpty(), "never more than 4 inside 60 seconds");
    }

    @Test
    void theWindowSlidesAndEachAddressIsCountedSeparately() {
        List<LogEvent> events = new ArrayList<>(failures("203.0.113.5", 3, 1));
        events.addAll(failures("198.51.100.1", 3, 1));
        assertTrue(run(events, BURST).isEmpty());

        List<LogEvent> late = new ArrayList<>(failures("203.0.113.5", 2, 1));
        for (int i = 0; i < 6; i++) {
            late.add(fail("203.0.113.5", "2026-11-12T03:30:0" + i + "Z"));
        }
        assertEquals("2026-11-12T03:30:00Z", run(late, BURST).get(0).windowStart());
    }

    @Test
    void aZeroWindowCountsTheWholeLogIncludingUntimedEvents() {
        AlertRule whole = new AlertRule("w", "w", "failed_logins", "global", 2, "gt", 0, Severity.LOW, null);
        List<LogEvent> events = List.of(fail("1.1.1.1", null), fail("2.2.2.2", null), fail("3.3.3.3", null));
        assertEquals(3, run(events, whole).get(0).value());
        assertTrue(run(events, BURST).isEmpty(), "a windowed rule ignores events without a time");
    }

    @Test
    void distinctPortsInsideAWindow() {
        AlertRule scan = new AlertRule("port-scan", "scan", "distinct_ports", "ip", 10, "gt", 10, Severity.HIGH, null);
        List<LogEvent> events = new ArrayList<>();
        for (int p = 0; p < 12; p++) {
            for (int repeat = 0; repeat < 2; repeat++) {
                events.add(new LogEvent("203.0.113.150", null, null, null, null, false, "raw",
                        Instant.parse("2026-11-12T04:10:00Z").plusSeconds(p * 10L + repeat), null,
                        LogFormat.FIREWALL, null, "firewall_block", null, 1000 + p));
            }
        }
        assertEquals(12, run(events, scan).get(0).value());
    }

    @Test
    void summaryLevelRulesAndTheGteOperator() {
        Finding compromised = new Finding("COMPROMISED_LOGIN", "Successful login after repeated failures",
                Severity.CRITICAL, null, 1, "d", List.of(), "r");
        AlertRule finding = new AlertRule("c", "compromised", "finding", "global", 0, "gt", 0, Severity.CRITICAL, "COMPROMISED_LOGIN");
        AlertRule risk = new AlertRule("r", "risk", "risk_score", "global", 70, "gte", 0, Severity.CRITICAL, null);

        List<Alert> alerts = AlertEngine.evaluate(List.of(), List.of(compromised), 70, List.of(finding, risk));
        assertEquals(2, alerts.size());
        assertTrue(AlertEngine.evaluate(List.of(), List.of(), 69, List.of(finding, risk)).isEmpty());
    }

    @Test
    void groupsByUserAndSortsMostSevereFirst() {
        AlertRule iam = new AlertRule("iam", "iam", "iam_changes", "user", 1, "gt", 10, Severity.MEDIUM, null);
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            events.add(new LogEvent("203.0.113.200", null, null, null, null, false, "raw",
                    Instant.parse("2026-11-12T06:07:0" + i + "Z"), "alice", LogFormat.CLOUDTRAIL, null, "iam_change", "CreateUser", null));
        }
        events.addAll(failures("203.0.113.5", 6, 1));
        List<Alert> alerts = run(events, iam, BURST);
        assertEquals("brute-force-burst", alerts.get(0).ruleId());
        assertEquals("alice", alerts.get(1).group());
    }
}
