package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogSummary;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportExporterTest {

    private final LogAnalysisService service = new LogAnalysisService(null);

    private LogSummary compromised() {
        List<LogEvent> events = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            events.add(new LogEvent("203.0.113.5", null, null, null, null, true,
                    "Failed password for admin from 203.0.113.5", null, "admin"));
        }
        events.add(new LogEvent("203.0.113.5", null, null, null, null, false,
                "Accepted password for admin from 203.0.113.5", null, "admin"));
        return service.summarize(events);
    }

    @Test
    void markdownCarriesRiskFindingsAndRecommendations() {
        String md = ReportExporter.markdown("auth.log", compromised());

        assertTrue(md.contains("# Log analysis report"));
        assertTrue(md.contains("**Risk:** CRITICAL"));
        assertTrue(md.contains("[CRITICAL] Successful login after repeated failures"));
        assertTrue(md.contains("T1078 Valid Accounts"));
        assertTrue(md.contains("**Recommendation:**"));
    }

    @Test
    void aCleanLogSaysSo() {
        LogSummary clean = service.summarize(List.of(
                new LogEvent("198.51.100.1", "GET", "/", 200, "Mozilla/5.0", false, "raw")));

        assertTrue(ReportExporter.markdown("ok.log", clean).contains("No findings. Traffic looks clean."));
    }

    @Test
    void textFromTheLogCannotInjectHtmlOrBreakTables() {
        LogSummary summary = service.summarize(List.of(
                new LogEvent("a|b", "GET", "/x'<script>alert(1)</script>", 500, "ua", false, "raw")));

        String md = ReportExporter.markdown("evil`name.log", summary);

        assertFalse(md.contains("<script>"));
        assertTrue(md.contains("&lt;script&gt;"));
        assertTrue(md.contains("a\\|b"));
        assertFalse(md.contains("evil`name"));
    }

    @Test
    void jsonExportIsValidAndHoldsTheSummary() throws Exception {
        JsonNode root = new ObjectMapper().readTree(ReportExporter.json("auth.log", compromised()));

        assertEquals("auth.log", root.get("file").asText());
        assertEquals("CRITICAL", root.get("summary").get("riskLevel").asText());
        assertTrue(root.get("summary").get("findings").size() > 0);
    }

    @Test
    void csvHasOneRowPerFindingWithEveryColumn() {
        String csv = ReportExporter.csv(compromised());
        String[] lines = csv.split("\r\n");

        assertEquals("severity,rule,title,mitre,count,description,evidence,recommendation", lines[0]);
        assertEquals(compromised().findings().size() + 1, lines.length);
        assertTrue(lines[1].startsWith("\"CRITICAL\",\"COMPROMISED_LOGIN\""));
        assertTrue(csv.contains("\"T1078 Valid Accounts\""));
    }

    @Test
    void csvCellsCannotRunAsSpreadsheetFormulas() {
        assertEquals("\"'=HYPERLINK(\"\"http://x\"\")\"", ReportExporter.csvCell("=HYPERLINK(\"http://x\")"));
        assertEquals("\"'+1\"", ReportExporter.csvCell("+1"));
        assertEquals("\"'@SUM(A1)\"", ReportExporter.csvCell("@SUM(A1)"));
        assertEquals("\"a b\"", ReportExporter.csvCell("a\r\nb"));
        assertEquals("\"\"", ReportExporter.csvCell(null));
    }

    @Test
    void markdownAndJsonIncludeACachedAiReportSafely() throws Exception {
        String md = ReportExporter.markdown("auth.log", compromised(), "## Executive summary\nBlock <b>203.0.113.5</b>");
        assertTrue(md.contains("## AI incident report"));
        assertTrue(md.contains("Block &lt;b&gt;203.0.113.5&lt;/b&gt;"));
        assertFalse(ReportExporter.markdown("auth.log", compromised(), null).contains("AI incident report"));

        JsonNode root = new ObjectMapper().readTree(ReportExporter.json("auth.log", compromised(), "text"));
        assertEquals("text", root.get("report").asText());
        assertFalse(new ObjectMapper().readTree(ReportExporter.json("auth.log", compromised())).has("report"));
    }
}
