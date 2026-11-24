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
}
