package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Alert;
import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogSummary;
import com.abhijeet.loganalyzer.model.Severity;
import com.abhijeet.loganalyzer.model.SuspiciousIp;
import com.abhijeet.loganalyzer.model.TimelinePoint;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds the PDF report with Apache PDFBox (Apache-2.0): overview, alerts, findings, top
 * offenders, charts drawn as vector bars, and the AI incident report when one has been generated.
 * Everything that came from the log is untrusted text and is reduced to printable Latin-1 first.
 */
public final class PdfReport {

    private static final float MARGIN = 48;
    private static final float WIDTH = PDRectangle.A4.getWidth() - 2 * MARGIN;
    private static final PDType1Font REGULAR = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
    private static final PDType1Font BOLD = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
    private static final PDType1Font MONO = new PDType1Font(Standard14Fonts.FontName.COURIER);

    private static final float[] TEXT = {0.11f, 0.10f, 0.09f};
    private static final float[] MUTED = {0.42f, 0.35f, 0.10f};
    private static final float[] YELLOW = {0.99f, 0.88f, 0.28f};
    private static final float[] BROWN = {0.63f, 0.38f, 0.03f};

    private final PDDocument doc = new PDDocument();
    private PDPageContentStream cs;
    private float y;
    private int pageNumber;

    private PdfReport() {
    }

    /** @param aiReport the LLM incident report, or null when none has been generated for this log */
    public static byte[] render(String fileName, LogSummary s, String aiReport) throws IOException {
        PdfReport pdf = new PdfReport();
        try {
            pdf.write(fileName, s, aiReport);
            pdf.cs.close();
            pdf.doc.getDocumentInformation().setTitle("Log analysis report - " + clean(fileName));
            pdf.doc.getDocumentInformation().setCreator("AI Log Analyzer");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            pdf.doc.save(out);
            return out.toByteArray();
        } finally {
            pdf.doc.close();
        }
    }

    private void write(String fileName, LogSummary s, String aiReport) throws IOException {
        newPage();
        // Title band
        fillRect(MARGIN, y - 54, WIDTH, 60, YELLOW);
        text(BOLD, 20, MARGIN + 12, y - 26, "Log analysis report", TEXT);
        text(REGULAR, 10, MARGIN + 12, y - 44, "Source: " + clean(fileName), TEXT);
        y -= 72;

        Severity level = levelOf(s.riskLevel());
        fillRect(MARGIN, y - 30, 150, 34, "CLEAN".equals(s.riskLevel()) ? new float[]{0.08f, 0.50f, 0.24f} : color(level));
        text(BOLD, 15, MARGIN + 10, y - 19, s.riskLevel() + " " + s.riskScore() + "/100", new float[]{1, 1, 1});
        line(REGULAR, 10, MARGIN + 166, "Detected format: " + clean(s.detectedFormat()), TEXT);
        y -= 2;
        line(REGULAR, 10, MARGIN + 166, s.totalLines() + " lines  |  " + s.uniqueIps() + " addresses  |  "
                + s.findings().size() + " findings  |  " + s.alerts().size() + " alerts", TEXT);
        if (s.firstSeen() != null) {
            line(REGULAR, 10, MARGIN + 166, "Period: " + s.firstSeen() + " to " + s.lastSeen(), MUTED);
        }
        y -= 18;

        heading("Triggered alerts");
        if (s.alerts().isEmpty()) {
            paragraph(REGULAR, 10, "No alert rule fired.", MUTED);
        }
        for (Alert a : s.alerts()) {
            badgeLine(a.severity(), a.name() + " - " + a.message());
        }

        heading("Findings");
        if (s.findings().isEmpty()) {
            paragraph(REGULAR, 10, "No findings. Traffic looks clean.", MUTED);
        }
        for (Finding f : s.findings()) {
            ensure(60);
            badgeLine(f.severity(), f.title() + "  (" + f.rule() + ", " + f.count() + " events)");
            if (f.mitre() != null) {
                paragraph(REGULAR, 9, "MITRE ATT&CK: " + f.mitre(), MUTED);
            }
            paragraph(REGULAR, 9.5f, f.description(), TEXT);
            for (String e : f.evidence()) {
                paragraph(MONO, 8, "  " + e, MUTED);
            }
            paragraph(BOLD, 9, "Fix: " + f.recommendation(), new float[]{0.08f, 0.40f, 0.20f});
            y -= 6;
        }

        heading("Top offenders");
        if (s.suspiciousIps().isEmpty()) {
            paragraph(REGULAR, 10, "No address did anything suspicious.", MUTED);
        }
        for (SuspiciousIp ip : s.suspiciousIps()) {
            String where = ip.country() != null
                    ? String.join(", ", nonNull(ip.city(), ip.country())) : ip.network();
            badgeLine(levelOf(ip.severity()), ip.ip() + "  score " + ip.score() + "  " + where);
            paragraph(REGULAR, 9, String.join("; ", ip.reasons()), MUTED);
        }
        if (s.geoipSource() != null) {
            paragraph(REGULAR, 8, "IP geolocation by DB-IP (db-ip.com), CC BY 4.0.", MUTED);
        }

        if (!s.timeline().isEmpty()) {
            heading("Requests over time (" + bucket(s.timelineBucketMinutes()) + " buckets, UTC)");
            chart(s.timeline(), false);
            heading("Errors over time");
            chart(s.timeline(), true);
            paragraph(REGULAR, 8, "Brown: requests. Red: spikes. Errors: orange 4xx, red 5xx, purple failed logins, "
                    + "blue app/system.", MUTED);
        }

        heading("Status codes and formats");
        paragraph(REGULAR, 9.5f, "Status codes: " + map(s.statusClasses()), TEXT);
        paragraph(REGULAR, 9.5f, "Formats: " + map(s.formats()), TEXT);

        heading("AI incident report");
        if (aiReport == null || aiReport.isBlank()) {
            paragraph(REGULAR, 10, "Not generated yet. Press \"Analyze with AI\" in the dashboard, then export again.", MUTED);
        } else {
            markdown(aiReport);
        }
        paragraph(REGULAR, 8, "Findings are computed deterministically from the log; the AI only writes the incident report.", MUTED);
    }

    // --------------------------------------------------------------- layout

    private void newPage() throws IOException {
        if (cs != null) {
            cs.close();
        }
        PDPage page = new PDPage(PDRectangle.A4);
        doc.addPage(page);
        cs = new PDPageContentStream(doc, page);
        pageNumber++;
        y = PDRectangle.A4.getHeight() - MARGIN;
        text(REGULAR, 8, MARGIN, 24, "AI Log Analyzer  |  page " + pageNumber, MUTED);
    }

    private void ensure(float needed) throws IOException {
        if (y - needed < MARGIN) {
            newPage();
        }
    }

    private void heading(String title) throws IOException {
        ensure(40);
        y -= 10;
        text(BOLD, 13, MARGIN, y - 12, title, TEXT);
        fillRect(MARGIN, y - 17, WIDTH, 1.2f, BROWN);
        y -= 26;
    }

    private void line(PDType1Font font, float size, float x, String value, float[] rgb) throws IOException {
        text(font, size, x, y - size, value, rgb);
        y -= size + 4;
    }

    private void badgeLine(Severity severity, String value) throws IOException {
        ensure(18);
        fillRect(MARGIN, y - 11, 56, 13, color(severity));
        text(BOLD, 7.5f, MARGIN + 4, y - 8, severity.name(), new float[]{1, 1, 1});
        List<String> lines = wrap(BOLD, 9.5f, clean(value), WIDTH - 64);
        for (String l : lines) {
            ensure(14);
            text(BOLD, 9.5f, MARGIN + 64, y - 9, l, TEXT);
            y -= 13;
        }
        y -= 2;
    }

    private void paragraph(PDType1Font font, float size, String value, float[] rgb) throws IOException {
        for (String l : wrap(font, size, clean(value), WIDTH)) {
            ensure(size + 4);
            text(font, size, MARGIN, y - size, l, rgb);
            y -= size + 3.5f;
        }
    }

    private void markdown(String report) throws IOException {
        for (String raw : report.split("\\R")) {
            String l = raw.strip().replace("**", "").replace("`", "");
            if (l.isEmpty()) {
                y -= 4;
            } else if (l.startsWith("#")) {
                y -= 4;
                paragraph(BOLD, 11, l.replaceFirst("^#+\\s*", ""), TEXT);
            } else if (l.startsWith("- ") || l.startsWith("* ")) {
                paragraph(REGULAR, 9.5f, "-  " + l.substring(2), TEXT);
            } else {
                paragraph(REGULAR, 9.5f, l, TEXT);
            }
        }
    }

    /** Bars drawn as vector rectangles; no image library needed. */
    private void chart(List<TimelinePoint> points, boolean errors) throws IOException {
        float height = 110;
        ensure(height + 24);
        float top = y;
        float bottom = y - height;
        int max = 1;
        for (TimelinePoint p : points) {
            max = Math.max(max, errors ? p.errors() : p.requests());
        }
        fillRect(MARGIN, bottom, WIDTH, 0.8f, MUTED);
        float bar = WIDTH / points.size();
        for (int i = 0; i < points.size(); i++) {
            TimelinePoint p = points.get(i);
            float x = MARGIN + i * bar + Math.min(0.6f, bar * 0.1f);
            float w = Math.max(0.6f, bar - Math.min(1.2f, bar * 0.2f));
            if (errors) {
                float base = bottom;
                int[] parts = {p.clientErrors(), p.serverErrors(), p.authFailures(), p.appErrors()};
                float[][] colors = {{0.85f, 0.47f, 0.02f}, {0.86f, 0.15f, 0.15f}, {0.49f, 0.23f, 0.93f}, {0.01f, 0.52f, 0.78f}};
                for (int k = 0; k < parts.length; k++) {
                    float h = height * parts[k] / max;
                    if (h > 0) {
                        fillRect(x, base, w, h, colors[k]);
                        base += h;
                    }
                }
            } else {
                float h = height * p.requests() / max;
                if (h > 0) {
                    fillRect(x, bottom, w, h, p.spike() ? new float[]{0.86f, 0.15f, 0.15f} : BROWN);
                }
            }
        }
        text(REGULAR, 7, MARGIN, top - 7, "max " + max, MUTED);
        text(REGULAR, 7, MARGIN, bottom - 10, label(points.get(0).start()), MUTED);
        String end = label(points.get(points.size() - 1).start());
        text(REGULAR, 7, MARGIN + WIDTH - REGULAR.getStringWidth(end) / 1000 * 7, bottom - 10, end, MUTED);
        y = bottom - 18;
    }

    // ------------------------------------------------------------ primitives

    private void text(PDType1Font font, float size, float x, float baseline, String value, float[] rgb) throws IOException {
        cs.beginText();
        cs.setFont(font, size);
        cs.setNonStrokingColor(rgb[0], rgb[1], rgb[2]);
        cs.newLineAtOffset(x, baseline);
        cs.showText(clean(value));
        cs.endText();
    }

    private void fillRect(float x, float yPos, float w, float h, float[] rgb) throws IOException {
        cs.setNonStrokingColor(rgb[0], rgb[1], rgb[2]);
        cs.addRect(x, yPos, w, h);
        cs.fill();
    }

    static List<String> wrap(PDType1Font font, float size, String value, float width) throws IOException {
        List<String> lines = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (String word : value.split(" ")) {
            String candidate = current.isEmpty() ? word : current + " " + word;
            if (font.getStringWidth(candidate) / 1000 * size <= width) {
                current.setLength(0);
                current.append(candidate);
                continue;
            }
            if (!current.isEmpty()) {
                lines.add(current.toString());
                current.setLength(0);
            }
            // A single word wider than the line (long URLs, payloads) is hard-split.
            String rest = word;
            while (font.getStringWidth(rest) / 1000 * size > width && rest.length() > 1) {
                int cut = rest.length();
                while (cut > 1 && font.getStringWidth(rest.substring(0, cut)) / 1000 * size > width) {
                    cut--;
                }
                lines.add(rest.substring(0, cut));
                rest = rest.substring(cut);
            }
            current.append(rest);
        }
        if (!current.isEmpty() || lines.isEmpty()) {
            lines.add(current.toString());
        }
        return lines;
    }

    /**
     * The standard PDF fonts only cover Latin-1, and log text can contain anything. Common
     * punctuation is mapped; other characters become '?' rather than failing the export.
     */
    static String clean(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '–', '—', '−' -> out.append('-');
                case '‘', '’' -> out.append('\'');
                case '“', '”' -> out.append('"');
                case '…' -> out.append("...");
                case '•', '·' -> out.append('-');
                case '→' -> out.append("->");
                case '\t' -> out.append(' ');
                default -> out.append((c >= 32 && c <= 126) || (c >= 160 && c <= 255) ? c : '?');
            }
        }
        return out.toString();
    }

    private static String map(Map<String, Integer> values) {
        if (values == null || values.isEmpty()) {
            return "none";
        }
        StringBuilder sb = new StringBuilder();
        values.forEach((k, v) -> sb.append(sb.isEmpty() ? "" : ", ").append(k).append(" ").append(v));
        return sb.toString();
    }

    private static List<String> nonNull(String... values) {
        List<String> list = new ArrayList<>();
        for (String v : values) {
            if (v != null) {
                list.add(v);
            }
        }
        return list;
    }

    private static String label(String iso) {
        return iso.length() >= 16 ? iso.substring(5, 16).replace('T', ' ') : iso;
    }

    private static String bucket(int minutes) {
        return minutes >= 1440 ? minutes / 1440 + "-day" : minutes >= 60 ? minutes / 60 + "-hour" : minutes + "-minute";
    }

    private static Severity levelOf(String level) {
        try {
            return Severity.valueOf(level);
        } catch (Exception e) {
            return Severity.LOW;
        }
    }

    private static float[] color(Severity s) {
        return switch (s) {
            case CRITICAL -> new float[]{0.86f, 0.15f, 0.15f};
            case HIGH -> new float[]{0.92f, 0.35f, 0.05f};
            case MEDIUM -> new float[]{0.85f, 0.47f, 0.02f};
            case LOW -> new float[]{0.01f, 0.52f, 0.78f};
        };
    }
}
