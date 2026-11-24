package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BoundedParsingTest {

    private final LogParser parser = new LogParser();

    private static String lines(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append("198.51.100.").append(i % 250).append(" - - [12/Nov/2026:08:00:00 +0000] \"GET /p").append(i)
                    .append(" HTTP/1.1\" 200 5 \"-\" \"ua\"\n");
        }
        return sb.toString();
    }

    @Test
    void longFilesAreSampledInsteadOfRejected() {
        LogParser.ParseResult result = parser.parse(lines(250) + "\n\n", null, 100);

        assertEquals(100, result.events().size());
        assertEquals(250, result.totalLines(), "blank lines are not counted");
        assertTrue(result.truncated());
        assertEquals("/p99", result.events().get(99).path(), "the first lines are kept");
    }

    @Test
    void shortFilesAreNotMarkedAsSampled() {
        LogParser.ParseResult result = parser.parse(lines(5), null, 100);
        assertEquals(5, result.events().size());
        assertFalse(result.truncated());
    }

    @Test
    void malformedLinesNeverFailTheParse() {
        String junk = String.join("\n",
                "{\"broken\": ",
                "{\"eventName\": 5, \"eventSource\": {}}",
                "[UFW BLOCK] SRC= DST= DPT=99999999999",
                "EventID=4625 TargetUserName= IpAddress=",
                "\u0000\u0001\u0002 binary �",
                "x".repeat(200_000),
                "2026-13-45T99:99:99Z ERROR nonsense",
                "13/45/2026 99:99:99 PM Microsoft-Windows-Security-Auditing,4625");

        List<LogEvent> events = parser.parse(junk);

        assertEquals(8, events.size());
        assertTrue(events.stream().allMatch(e -> e.raw() != null));
    }

    @Test
    void aForcedFormatIsUsedForEveryLineAndMisfitsBecomeUnrecognised() {
        String log = "Nov 12 03:20:11 web01 sshd[2411]: Failed password for root from 203.0.113.5 port 1 ssh2\n"
                + "203.0.113.45 - - [12/Nov/2026:08:09:03 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"ua\"";

        List<LogEvent> asApache = parser.parse(log, LogFormat.APACHE, 100).events();
        assertEquals(LogFormat.UNKNOWN, asApache.get(0).format());
        assertEquals("203.0.113.5", asApache.get(0).ip(), "the address is still extracted");
        assertEquals(LogFormat.APACHE, asApache.get(1).format());

        List<LogEvent> asFirewall = parser.parse(log, LogFormat.FIREWALL, 100).events();
        assertTrue(asFirewall.stream().allMatch(e -> e.format() == LogFormat.UNKNOWN));

        List<LogEvent> asContainer = parser.parse("something happened", LogFormat.CONTAINER, 100).events();
        assertEquals(LogFormat.CONTAINER, asContainer.get(0).format(), "container is the catch-all a user can force");
    }

    @Test
    void aCloudTrailDocumentIsOnlyReadAsADocumentWhenTheFormatAllowsIt() {
        String doc = "{\"Records\":[{\"eventName\":\"ListBuckets\",\"eventSource\":\"s3.amazonaws.com\"}]}";
        assertEquals(LogFormat.CLOUDTRAIL, parser.parse(doc, LogFormat.CLOUDTRAIL, 10).events().get(0).format());
        assertEquals(LogFormat.UNKNOWN, parser.parse(doc, LogFormat.FIREWALL, 10).events().get(0).format());
    }
}
