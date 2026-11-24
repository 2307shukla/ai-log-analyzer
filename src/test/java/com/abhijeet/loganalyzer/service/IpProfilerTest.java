package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.GeoLocation;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import com.abhijeet.loganalyzer.model.SuspiciousIp;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpProfilerTest {

    /** A fake offline database: knows one public address. */
    private static final GeoLookup FAKE_GEO = new GeoLookup() {
        @Override
        public Optional<GeoLocation> lookup(String ip) {
            return "8.8.8.8".equals(ip) ? Optional.of(new GeoLocation("Testland", "ZZ", "Test City")) : Optional.empty();
        }

        @Override
        public String source() {
            return "test";
        }
    };

    private static LogEvent fail(String ip) {
        return new LogEvent(ip, null, null, null, null, true, "Failed password for root from " + ip, null, "root",
                LogFormat.SSH, null, "logon_failure", null, null);
    }

    private static LogEvent ok(String ip) {
        return new LogEvent(ip, null, null, null, null, false, "Accepted password for root from " + ip, null, "root",
                LogFormat.SSH, null, "logon_success", null, null);
    }

    private static LogEvent web(String ip, String path, int status, String ua) {
        return new LogEvent(ip, "GET", path, status, ua, false, "raw");
    }

    @Test
    void aBreakInScoresCriticalWithItsReasons() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            events.add(fail("8.8.8.8"));
        }
        events.add(ok("8.8.8.8"));

        SuspiciousIp top = IpProfiler.profile(events, FAKE_GEO).get(0);

        assertEquals("8.8.8.8", top.ip());
        assertEquals(40 + 10 + 9, top.score());
        assertEquals("HIGH", top.severity());
        assertEquals("logged in after 9 failed attempts", top.reasons().get(0));
        assertEquals("Testland", top.country());
        assertEquals("Test City", top.city());
        assertEquals("Public", top.network());
    }

    @Test
    void scoresWebAttacksScannersAndProbes() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            events.add(web("203.0.113.45", "/p?id=1%27%20OR%201=1", 500, "sqlmap/1.7"));
        }
        events.add(web("203.0.113.45", "/.env", 404, "sqlmap/1.7"));

        SuspiciousIp s = IpProfiler.profile(events, FAKE_GEO).get(0);

        // 15 + 15 (attacks) + 15 (scanner) + 6 (probe) + 5 (server errors)
        assertEquals(56, s.score());
        assertEquals(6, s.attackRequests());
        assertEquals(1, s.probes());
        assertEquals("Documentation range", s.network());
        assertNull(s.country(), "no location for documentation addresses");
    }

    @Test
    void scoresPortScansAndIsCappedAtOneHundred() {
        List<LogEvent> events = new ArrayList<>();
        for (int p = 1; p <= 30; p++) {
            events.add(new LogEvent("198.51.100.9", null, null, null, null, true, "raw", null, null,
                    LogFormat.FIREWALL, null, "firewall_block", null, p));
            events.add(fail("198.51.100.9"));
        }
        events.add(ok("198.51.100.9"));
        SuspiciousIp s = IpProfiler.profile(events, GeoLookup.NONE).get(0);
        assertEquals(100, s.score());
        assertEquals("CRITICAL", s.severity());
        assertEquals(30, s.portsProbed());
    }

    @Test
    void harmlessTrafficIsNotListedAndTheTableIsBounded() {
        List<LogEvent> events = new ArrayList<>();
        events.add(web("192.0.2.1", "/", 200, "Mozilla/5.0"));
        for (int i = 0; i < 15; i++) {
            for (int j = 0; j < 3; j++) {
                events.add(fail("198.51.100." + i));
            }
        }
        List<SuspiciousIp> list = IpProfiler.profile(events, GeoLookup.NONE);
        assertEquals(IpProfiler.TOP, list.size());
        assertTrue(list.stream().noneMatch(s -> s.ip().equals("192.0.2.1")));
    }

    @Test
    void hostNamesAreIgnoredSoNothingIsEverResolved() {
        assertTrue(IpProfiler.profile(List.of(fail("evil.example.com"), fail("evil.example.com"),
                fail("evil.example.com")), FAKE_GEO).isEmpty());
    }
}
