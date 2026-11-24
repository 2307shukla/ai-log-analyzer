package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogSummary;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfReportTest {

    private final LogParser parser = new LogParser();
    private final LogAnalysisService service = new LogAnalysisService(null);

    private LogSummary sample(String resource) throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/" + resource)) {
            return service.summarize(parser.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
        }
    }

    private static String text(byte[] pdf) throws Exception {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            return new PDFTextStripper().getText(doc);
        }
    }

    @Test
    void containsStatsFindingsChartsAndTheAiReport() throws Exception {
        byte[] pdf = PdfReport.render("ssh-auth.log", sample("samples/ssh-auth.log"),
                "## Executive summary\n- **203.0.113.5** broke in as `admin` after 11 failures.");
        String text = text(pdf);

        assertTrue(new String(pdf, 0, 5, StandardCharsets.US_ASCII).startsWith("%PDF-"));
        assertTrue(text.contains("Log analysis report"));
        assertTrue(text.contains("Source: ssh-auth.log"));
        assertTrue(text.contains("CRITICAL 100/100"));
        assertTrue(text.contains("Detected format: SSH auth"));
        assertTrue(text.contains("COMPROMISED_LOGIN"));
        assertTrue(text.contains("T1110 Brute Force"));
        assertTrue(text.contains("Top offenders"));
        assertTrue(text.contains("Requests over time"));
        assertTrue(text.contains("AI incident report"));
        assertTrue(text.contains("203.0.113.5 broke in as admin after 11 failures."), "markdown is flattened");
    }

    @Test
    void explainsWhenNoAiReportExistsYet() throws Exception {
        assertTrue(text(PdfReport.render("x.log", sample("samples/ufw-firewall.log"), null)).contains("Not generated yet"));
    }

    @Test
    void untrustedTextOutsideLatin1NeverBreaksTheExport() throws Exception {
        String hostile = "\u4e2d\u6587 \uD83D\uDE00 \u0000\u0007 \u2013dash\u2014 \u201Cq\u201D " + "x".repeat(400);
        List<LogEvent> events = parser.parse(
                "203.0.113.45 - - [12/Nov/2026:08:09:03 +0000] \"GET /p?id=1%27" + hostile.replace(' ', '_')
                        + " HTTP/1.1\" 500 5 \"-\" \"" + hostile + "\"");
        byte[] pdf = PdfReport.render(hostile + ".log", service.summarize(events), hostile);
        String text = text(pdf);
        assertTrue(text.contains("-dash-"));
        assertTrue(text.contains("SQL_INJECTION"));
    }

    @Test
    void cleanMapsPunctuationAndReplacesTheRest() {
        assertEquals("a-b \"c\" ... ->", PdfReport.clean("a\u2013b \u201Cc\u201D \u2026 \u2192"));
        assertEquals("? ? caf\u00e9", PdfReport.clean("\u4e2d \u0007 caf\u00e9"));
    }

    @Test
    void everySampleRendersAndCopiesAreKeptForReview() throws Exception {
        Path out = Path.of("target", "report-samples");
        Files.createDirectories(out);
        for (String name : List.of("apache-access.log", "ssh-auth.log", "linux-syslog.log", "json-lines.jsonl",
                "spring-boot.log", "windows-security.log", "cloudtrail.json", "ufw-firewall.log", "kubernetes.log")) {
            byte[] pdf = PdfReport.render(name, sample("samples/" + name), null);
            assertTrue(pdf.length > 1_000, name);
            Files.write(out.resolve(name + ".pdf"), pdf);
        }
    }
}
