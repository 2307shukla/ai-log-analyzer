package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/** Uploaded logs are untrusted: crafted lines must not make the patterns backtrack for long. */
class HostileInputTest {

    private final LogParser parser = new LogParser();

    private static final int N = 50_000;

    /** Lines shaped like CodeQL's worst cases for each pattern, each tens of thousands of characters long. */
    private static List<String> hostileLines() {
        String bang = "!".repeat(N);
        String spaces = " ".repeat(N);
        return List.of(
                "! ! ! [\\] \"! !" + bang,                                   // access log request line
                "2026-11-12T08:00:01Z ERROR" + spaces + " x",            // Spring Boot level and message
                "2026-11-12 08:00:01,123 [main] ERROR" + spaces + " x", // Logback
                "Nov 12 03:20:11 host prog:" + spaces + " x",           // syslog header
                "Nov 12 03:20:11" + spaces,
                "2026-11-12T08:00:01Z ERROR b" + "b$.".repeat(N),             // exception name search
                "Nov 12 03:20:11 host sudo: ! : COMMAND=" + "COMMAND=a".repeat(N / 4),
                "2026-11-12T08:00:01Z ERROR first line, so the next ones are read as a stack trace",
                "a.".repeat(N) + "FooException: deep package",               // exception header
                "Caused by: " + "a.".repeat(N) + "Boom");                     // caused-by line
    }

    @Test
    void crafted_lines_parse_quickly_in_every_format() {
        String content = String.join("\n", hostileLines());
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            parser.parse(content);
            for (LogFormat format : LogFormat.values()) {
                parser.parse(content, format, 1000);
            }
        });
    }

    @Test
    void sudo_lines_give_the_user_and_the_last_command() {
        assertArrayEquals(new String[] {"alice", "/bin/ls -la"},
                LogParser.sudoCommand("  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls -la"));
        assertArrayEquals(new String[] {"bob", "/usr/bin/id"},
                LogParser.sudoCommand("bob : COMMAND=/bin/echo ; COMMAND=/usr/bin/id"));
        assertNull(LogParser.sudoCommand("alice bob : COMMAND=/bin/ls"), "the user is a single word");
        assertNull(LogParser.sudoCommand("COMMAND=/bin/ls : alice"), "COMMAND= must come after the separator");
        assertNull(LogParser.sudoCommand("pam_unix(sudo:auth): authentication failure; user=alice"));
    }

    @Test
    void exception_names_are_found_as_before() {
        assertEquals("java.lang.IllegalStateException",
                LogParser.exceptionName("Request failed: java.lang.IllegalStateException: boom"));
        assertEquals("com.example.orders.OrderNotFoundException",
                LogParser.exceptionName("Caused by com.example.orders.OrderNotFoundException."));
        assertEquals("x.y.FooError", LogParser.exceptionName("see x.y.FooError.details"));
        assertNull(LogParser.exceptionName("IllegalStateException without a package"));
        assertNull(LogParser.exceptionName("nothing to see here"));
    }

    @Test
    void absurd_numeric_timestamps_are_ignored_not_truncated() {
        for (String value : List.of("1e300", "-5", "NaN", "Infinity", "99999999999999999999")) {
            List<LogEvent> events = parser.parse("{\"timestamp\":\"" + value + "\",\"message\":\"x\"}");
            assertEquals(1, events.size());
            assertNull(events.get(0).timestamp(), value);
        }
        List<LogEvent> ok = parser.parse("{\"timestamp\":1794900000,\"message\":\"x\"}");
        assertEquals(1794900000L, ok.get(0).timestamp().getEpochSecond());
    }
}
