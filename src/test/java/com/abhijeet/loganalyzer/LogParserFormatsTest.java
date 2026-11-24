package com.abhijeet.loganalyzer;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.service.LogParser;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogParserFormatsTest {

    private static final String SSH_FAIL =
            "Nov 12 03:20:11 web01 sshd[2411]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2";

    private LogParser parserAt(String instant) {
        return new LogParser(Clock.fixed(Instant.parse(instant), ZoneOffset.UTC));
    }

    private LogEvent one(LogParser parser, String line) {
        List<LogEvent> events = parser.parse(line);
        assertEquals(1, events.size());
        return events.get(0);
    }

    @Test
    void readsTheTimeOfApacheLinesAndConvertsOffsets() {
        LogParser parser = new LogParser();

        LogEvent utc = one(parser, "203.0.113.45 - - [12/Nov/2026:08:09:03 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"ua\"");
        LogEvent ist = one(parser, "203.0.113.45 - - [12/Nov/2026:13:39:03 +0530] \"GET / HTTP/1.1\" 200 5 \"-\" \"ua\"");

        assertEquals(Instant.parse("2026-11-12T08:09:03Z"), utc.timestamp());
        assertEquals(Instant.parse("2026-11-12T08:09:03Z"), ist.timestamp());
    }

    @Test
    void syslogLinesGetTheYearFromTheClockAndTheUsername() {
        LogEvent event = one(parserAt("2026-06-01T00:00:00Z"), SSH_FAIL);

        assertEquals(Instant.parse("2026-11-12T03:20:11Z"), event.timestamp());
        assertEquals("admin", event.user());
        assertEquals("203.0.113.5", event.ip());
        assertTrue(event.authFailure());
    }

    @Test
    void syslogYearFollowsTheDatedLinesInTheSameFile() {
        LogParser parser = parserAt("2030-01-01T00:00:00Z");
        String file = "203.0.113.45 - - [12/Nov/2026:08:09:03 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"ua\"\n" + SSH_FAIL;

        List<LogEvent> events = parser.parse(file);

        assertEquals(Instant.parse("2026-11-12T03:20:11Z"), events.get(1).timestamp());
    }

    @Test
    void extractsTheAccountFromCommonSshLineShapes() {
        LogParser parser = new LogParser();

        assertEquals("root", one(parser, "Nov 12 03:20:11 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2").user());

        LogEvent accepted = one(parser, "Nov 12 03:21:02 h sshd[2]: Accepted publickey for deploy from 192.168.1.31 port 1 ssh2");
        assertEquals("deploy", accepted.user());
        assertFalse(accepted.authFailure());

        LogEvent invalid = one(parser, "Nov 12 03:22:00 h sshd[3]: Invalid user test from 1.1.1.1 port 22");
        assertEquals("test", invalid.user());
        assertTrue(invalid.authFailure());
    }

    @Test
    void readsJsonLines() {
        LogEvent event = one(new LogParser(),
                "{\"time\":\"2026-11-12T08:15:02Z\",\"remote_addr\":\"198.51.100.77\",\"method\":\"GET\","
                        + "\"uri\":\"/api/orders\",\"status\":200,\"user_agent\":\"curl/8.4.0\"}");

        assertEquals("198.51.100.77", event.ip());
        assertEquals("GET", event.method());
        assertEquals("/api/orders", event.path());
        assertEquals(200, event.status());
        assertEquals("curl/8.4.0", event.userAgent());
        assertEquals(Instant.parse("2026-11-12T08:15:02Z"), event.timestamp());
    }

    @Test
    void readsNginxStyleJsonWithAStringStatusAndTheRequestLine() {
        LogEvent event = one(new LogParser(),
                "{\"request\":\"GET /x HTTP/1.1\",\"status\":\"500\",\"remote_addr\":\"1.2.3.4\","
                        + "\"time_iso8601\":\"2026-11-12T08:15:02+00:00\"}");

        assertEquals("GET", event.method());
        assertEquals("/x", event.path());
        assertEquals(500, event.status());
        assertEquals(Instant.parse("2026-11-12T08:15:02Z"), event.timestamp());
    }

    @Test
    void readsEpochTimestampsInJson() {
        LogEvent event = one(new LogParser(), "{\"ip\":\"1.2.3.4\",\"ts\":1700000000}");
        assertEquals(Instant.ofEpochSecond(1_700_000_000L), event.timestamp());
    }

    @Test
    void brokenJsonFallsBackToTheGenericParserAndKeepsTheLine() {
        LogEvent event = one(new LogParser(), "{not json 10.0.0.1}");

        assertEquals("10.0.0.1", event.ip());
        assertEquals("{not json 10.0.0.1}", event.raw());
        assertNull(event.timestamp());
    }

    @Test
    void theShortConstructorLeavesTimeAndUserEmpty() {
        LogEvent event = new LogEvent("1.1.1.1", "GET", "/", 200, "ua", false, "raw");

        assertNull(event.timestamp());
        assertNull(event.user());
    }
}
