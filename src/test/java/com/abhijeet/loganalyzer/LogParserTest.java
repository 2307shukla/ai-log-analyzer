package com.abhijeet.loganalyzer;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.service.LogParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogParserTest {

    private final LogParser parser = new LogParser();

    @Test
    void parsesApacheCombinedFormat() {
        String line = "203.0.113.45 - - [12/Nov/2026:08:09:03 +0000] "
                + "\"GET /product?id=1 HTTP/1.1\" 500 512 \"-\" \"sqlmap/1.7\"";

        List<LogEvent> events = parser.parse(line);

        assertEquals(1, events.size());
        LogEvent event = events.get(0);
        assertEquals("203.0.113.45", event.ip());
        assertEquals("GET", event.method());
        assertEquals("/product?id=1", event.path());
        assertEquals(500, event.status());
        assertEquals("sqlmap/1.7", event.userAgent());
    }

    @Test
    void detectsSshAuthenticationFailure() {
        String line = "Nov 12 03:20:11 web01 sshd[2411]: Failed password for invalid user "
                + "admin from 203.0.113.5 port 51234 ssh2";

        List<LogEvent> events = parser.parse(line);

        assertEquals(1, events.size());
        assertTrue(events.get(0).authFailure());
        assertEquals("203.0.113.5", events.get(0).ip());
    }

    @Test
    void keepsUnrecognisedLinesWithTheirIp() {
        List<LogEvent> events = parser.parse("some unknown format mentioning 10.0.0.1 here");

        assertEquals(1, events.size());
        assertEquals("10.0.0.1", events.get(0).ip());
        assertFalse(events.get(0).authFailure());
    }

    @Test
    void handlesEmptyInput() {
        assertTrue(parser.parse("").isEmpty());
        assertTrue(parser.parse(null).isEmpty());
        assertTrue(parser.parse("   \n\n  ").isEmpty());
    }
}
