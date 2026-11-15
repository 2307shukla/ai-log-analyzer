package com.abhijeet.loganalyzer;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogSummary;
import com.abhijeet.loganalyzer.service.LogAnalysisService;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the detection rules - the actual product logic.
 *
 * The parser has its own tests; these cover what the rules conclude from parsed
 * events, which is what a reviewer would challenge in an interview.
 */
class LogAnalysisServiceTest {

    /** summarize() never touches the model, so it can be null here. */
    private final LogAnalysisService service = new LogAnalysisService(null);

    private LogEvent web(String ip, String path, int status) {
        return new LogEvent(ip, "GET", path, status, "test-agent", false, "raw");
    }

    private LogEvent authFailure(String ip) {
        return new LogEvent(ip, null, null, null, null, true, "Failed password for root");
    }

    private boolean hasSignal(List<String> signals, String fragment) {
        return signals.stream().anyMatch(s -> s.toLowerCase().contains(fragment.toLowerCase()));
    }

    @Test
    void flagsBruteForceAtThreeOrMoreFailures() {
        List<LogEvent> events = List.of(
                authFailure("203.0.113.5"),
                authFailure("203.0.113.5"),
                authFailure("203.0.113.5"));

        LogSummary summary = service.summarize(events);

        assertTrue(hasSignal(summary.signals(), "brute-force"));
        assertEquals(3, summary.authFailuresByIp().get("203.0.113.5"));
    }

    @Test
    void doesNotFlagTwoFailuresAsBruteForce() {
        List<LogEvent> events = List.of(
                authFailure("203.0.113.5"),
                authFailure("203.0.113.5"));

        assertFalse(hasSignal(service.summarize(events).signals(), "brute-force"));
    }

    @Test
    void flagsInjectionAndScannerPaths() {
        List<LogEvent> events = List.of(
                web("203.0.113.45", "/product?id=1' OR '1'='1", 500),
                web("45.155.205.233", "/.env", 404),
                web("45.155.205.233", "/../../etc/passwd", 400));

        LogSummary summary = service.summarize(events);

        assertTrue(hasSignal(summary.signals(), "injection or scanning"));
        assertEquals(3, summary.suspiciousPaths().size());
    }

    @Test
    void flagsClusteredServerErrors() {
        List<LogEvent> events = List.of(
                web("198.51.100.7", "/a", 500),
                web("198.51.100.7", "/b", 500),
                web("198.51.100.7", "/c", 500));

        LogSummary summary = service.summarize(events);

        assertTrue(hasSignal(summary.signals(), "server errors"));
        assertEquals(3, summary.statusClasses().get("5xx"));
    }

    @Test
    void flagsTrafficConcentrationFromOneAddress() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            events.add(web("203.0.113.99", "/page" + i, 200));
        }

        LogSummary summary = service.summarize(events);

        assertTrue(hasSignal(summary.signals(), "concentrated traffic"));
    }

    @Test
    void cleanTrafficProducesNoSignals() {
        List<LogEvent> events = List.of(
                web("198.51.100.7", "/products", 200),
                web("198.51.100.7", "/cart", 200),
                web("198.51.100.8", "/products", 200));

        LogSummary summary = service.summarize(events);

        assertTrue(summary.signals().isEmpty(),
                "expected no signals but got: " + summary.signals());
    }

    @Test
    void countsLinesAndStatusClasses() {
        List<LogEvent> events = List.of(
                web("198.51.100.7", "/a", 200),
                web("198.51.100.7", "/b", 404),
                web("198.51.100.7", "/c", 500));

        LogSummary summary = service.summarize(events);

        assertEquals(3, summary.totalLines());
        assertEquals(3, summary.parsedEvents());
        assertEquals(1, summary.statusClasses().get("2xx"));
        assertEquals(1, summary.statusClasses().get("4xx"));
        assertEquals(1, summary.statusClasses().get("5xx"));
    }
}
