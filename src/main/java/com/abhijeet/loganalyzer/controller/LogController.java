package com.abhijeet.loganalyzer.controller;

import com.abhijeet.loganalyzer.model.ChatRequest;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import com.abhijeet.loganalyzer.service.LogAnalysisService;
import com.abhijeet.loganalyzer.service.LogParser;
import com.abhijeet.loganalyzer.service.LogStore;
import com.abhijeet.loganalyzer.model.LogSummary;
import com.abhijeet.loganalyzer.service.PdfReport;
import com.abhijeet.loganalyzer.service.ReportCache;
import com.abhijeet.loganalyzer.service.ReportExporter;
import com.abhijeet.loganalyzer.service.SampleCatalog;
import com.abhijeet.loganalyzer.service.Timeline;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Tag(name = "Logs", description = "Upload a log, get findings, and download a report")
@RestController
@RequestMapping("/api/logs")
public class LogController {

    /** Lines analysed per upload; longer files are sampled (first lines) so memory stays bounded. */
    static final int MAX_LINES = 100_000;

    private final LogParser parser;
    private final LogAnalysisService analysisService;
    private final LogStore store;
    private final SampleCatalog samples;
    private final ReportCache reports;

    public LogController(LogParser parser, LogAnalysisService analysisService, LogStore store,
                         SampleCatalog samples, ReportCache reports) {
        this.parser = parser;
        this.analysisService = analysisService;
        this.store = store;
        this.samples = samples;
        this.reports = reports;
    }

    /** Upload a log file. Parsing is deterministic - no AI call, so this is instant and free. */
    @Operation(summary = "Upload a log of any supported format; detected automatically unless format is given. "
            + "Kept private to your session. Maximum 5 MB; files over 100,000 lines are sampled.")
    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> upload(@RequestParam("file") MultipartFile file,
                                                      @RequestParam(defaultValue = "auto") String format,
                                                      HttpServletRequest request)
            throws IOException {
        LogFormat forced;
        try {
            forced = format(format);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }

        String content = new String(file.getBytes(), StandardCharsets.UTF_8);
        LogParser.ParseResult parsed = parser.parse(content, forced, MAX_LINES);

        if (parsed.events().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "No usable log lines found in the uploaded file."));
        }

        String sessionId = request.getSession(true).getId();
        store.set(sessionId, file.getOriginalFilename(), parsed.events());
        return ResponseEntity.ok(loaded(store.name(sessionId), parsed, forced));
    }

    /** The formats the parser knows, for the manual override. */
    @Operation(summary = "List the log formats that can be detected or forced")
    @GetMapping("/formats")
    public List<Map<String, String>> formats() {
        List<Map<String, String>> list = new java.util.ArrayList<>();
        list.add(Map.of("id", "auto", "label", "Auto-detect"));
        for (LogFormat f : LogFormat.values()) {
            if (f != LogFormat.UNKNOWN) {
                list.add(Map.of("id", f.name().toLowerCase(java.util.Locale.ROOT), "label", f.label()));
            }
        }
        return list;
    }

    /**
     * Re-reads the loaded log as the given format (or auto-detects again). Visitors looking at the
     * bundled sample get their own copy, so the override never affects anyone else.
     */
    @Operation(summary = "Re-parse the loaded log with a manual format override (format=auto to detect again)")
    @PostMapping("/format")
    public ResponseEntity<Map<String, Object>> override(@RequestParam String format, HttpServletRequest request) {
        LogFormat forced;
        try {
            forced = format(format);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
        String current = sessionId(request);
        if (store.isEmpty(current)) {
            return ResponseEntity.ok(Map.of("message", "No log loaded. Upload a file to begin."));
        }
        String name = store.name(current);
        StringBuilder raw = new StringBuilder();
        for (LogEvent e : store.get(current)) {
            raw.append(e.raw()).append('\n');
        }
        LogParser.ParseResult parsed = parser.parse(raw.toString(), forced, MAX_LINES);

        String sessionId = request.getSession(true).getId();
        store.set(sessionId, name, parsed.events());
        return ResponseEntity.ok(loaded(name, parsed, forced));
    }

    private Map<String, Object> loaded(String name, LogParser.ParseResult parsed, LogFormat forced) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("file", name);
        body.put("loaded", parsed.events().size());
        body.put("totalLines", parsed.totalLines());
        body.put("sampled", parsed.truncated());
        body.put("format", forced == null ? "auto" : forced.name().toLowerCase(java.util.Locale.ROOT));
        body.put("summary", analysisService.summarize(parsed.events()));
        return body;
    }

    /** "auto" means detect per line; anything else must name a format. */
    static LogFormat format(String value) {
        if (value == null || value.isBlank() || "auto".equalsIgnoreCase(value)) {
            return null;
        }
        try {
            LogFormat f = LogFormat.valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
            if (f == LogFormat.UNKNOWN) {
                throw new IllegalArgumentException();
            }
            return f;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown format. Use auto or one of: " + java.util.Arrays.stream(LogFormat.values())
                    .filter(f -> f != LogFormat.UNKNOWN).map(f -> f.name().toLowerCase(java.util.Locale.ROOT))
                    .collect(java.util.stream.Collectors.joining(", ")) + ".");
        }
    }

    /** The bundled example logs, one per supported format. */
    @Operation(summary = "List the bundled sample logs")
    @GetMapping("/samples")
    public List<SampleCatalog.Info> samples() {
        return samples.list();
    }

    /** Loads a bundled sample into the caller's session, as if they had uploaded it. */
    @Operation(summary = "Load a bundled sample log into your session")
    @PostMapping("/samples/{id}")
    public ResponseEntity<Map<String, Object>> loadSample(@PathVariable String id, HttpServletRequest request) {
        return samples.get(id)
                .map(sample -> {
                    String sessionId = request.getSession(true).getId();
                    store.set(sessionId, sample.file(), sample.events());
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("file", sample.file());
                    body.put("loaded", sample.events().size());
                    body.put("summary", analysisService.summarize(sample.events()));
                    return ResponseEntity.ok(body);
                })
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error", "Unknown sample.")));
    }

    /** Requests and errors over time, per minute, per hour, or with an automatic bucket size. */
    @Operation(summary = "Requests and errors over time with spike flags; bucket = auto, minute or hour")
    @GetMapping("/timeline")
    public ResponseEntity<Map<String, Object>> timeline(@RequestParam(defaultValue = "auto") String bucket,
                                                        HttpServletRequest request) {
        int minutes = switch (bucket.toLowerCase(java.util.Locale.ROOT)) {
            case "auto" -> 0;
            case "minute" -> 1;
            case "hour" -> 60;
            default -> -1;
        };
        if (minutes < 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "bucket must be auto, minute or hour."));
        }
        String sessionId = sessionId(request);
        if (store.isEmpty(sessionId)) {
            return ResponseEntity.ok(Map.of("message", "No log loaded. Upload a file to begin."));
        }
        Timeline.Result result;
        try {
            result = Timeline.build(store.get(sessionId), minutes);
        } catch (Timeline.TooManyPointsException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("file", store.name(sessionId));
        body.put("bucketMinutes", result.bucketMinutes());
        body.put("points", result.points());
        return ResponseEntity.ok(body);
    }

    /** Statistics only - no AI call, no quota used. */
    @Operation(summary = "Findings, risk score and timeline - no AI call")
    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> summary(HttpServletRequest request) {
        String sessionId = sessionId(request);
        if (store.isEmpty(sessionId)) {
            return ResponseEntity.ok(Map.of("message", "No log loaded. Upload a file to begin."));
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("file", store.name(sessionId));
        body.put("summary", analysisService.summarize(store.get(sessionId)));
        return ResponseEntity.ok(body);
    }

    /** Full analysis: deterministic stats plus the LLM-written report. */
    @Operation(summary = "Findings plus the AI-written incident report")
    @GetMapping("/analyze")
    public ResponseEntity<Map<String, Object>> analyze(HttpServletRequest request) {
        String sessionId = sessionId(request);
        if (store.isEmpty(sessionId)) {
            return ResponseEntity.ok(Map.of("message", "No log loaded. Upload a file to begin."));
        }

        List<LogEvent> events = store.get(sessionId);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("file", store.name(sessionId));
        body.put("summary", analysisService.summarize(events));
        String report = analysisService.analyze(events);
        reports.put(sessionId, events, report);
        body.put("report", report);
        return ResponseEntity.ok(body);
    }

    /** Ask a question about the loaded log. Answers are grounded in the computed summary. */
    @Operation(summary = "Ask a question about the loaded log (AI call, rate limited)")
    @PostMapping("/chat")
    public ResponseEntity<Map<String, Object>> chat(@RequestBody ChatRequest chat, HttpServletRequest request) {
        String question = chat == null ? null : chat.question();
        if (question == null || question.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Type a question first."));
        }
        if (question.length() > LogAnalysisService.MAX_QUESTION) {
            return ResponseEntity.badRequest().body(Map.of("error",
                    "Question too long. Maximum is " + LogAnalysisService.MAX_QUESTION + " characters."));
        }
        String sessionId = sessionId(request);
        if (store.isEmpty(sessionId)) {
            return ResponseEntity.ok(Map.of("message", "No log loaded. Upload a file to begin."));
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("file", store.name(sessionId));
        body.put("answer", analysisService.ask(store.get(sessionId), question, chat.history()));
        return ResponseEntity.ok(body);
    }

    /**
     * Downloadable report built from the deterministic findings, plus the AI incident report when
     * one was already generated for this log. Never calls the model, so it uses no quota.
     */
    @Operation(summary = "Download the report: format=pdf (stats, charts, findings, AI report), md, json, "
            + "or csv (findings only). No AI call.")
    @GetMapping("/export")
    public ResponseEntity<byte[]> export(@RequestParam(defaultValue = "md") String format,
                                         HttpServletRequest request) throws IOException {
        String sessionId = sessionId(request);
        if (store.isEmpty(sessionId)) {
            return error(404, "No log loaded. Upload a file to begin.");
        }

        List<LogEvent> events = store.get(sessionId);
        LogSummary summary = analysisService.summarize(events);
        String name = store.name(sessionId);
        String aiReport = reports.get(sessionId, events);

        // The download name is fixed, never taken from the uploaded file name.
        return switch (format.toLowerCase(java.util.Locale.ROOT)) {
            case "md" -> download("log-analysis-report.md", new MediaType("text", "markdown", StandardCharsets.UTF_8),
                    ReportExporter.markdown(name, summary, aiReport).getBytes(StandardCharsets.UTF_8));
            case "json" -> download("log-analysis-report.json", MediaType.APPLICATION_JSON,
                    ReportExporter.json(name, summary, aiReport).getBytes(StandardCharsets.UTF_8));
            case "csv" -> download("log-analysis-findings.csv", new MediaType("text", "csv", StandardCharsets.UTF_8),
                    ReportExporter.csv(summary).getBytes(StandardCharsets.UTF_8));
            case "pdf" -> download("log-analysis-report.pdf", MediaType.APPLICATION_PDF,
                    PdfReport.render(name, summary, aiReport));
            default -> error(400, "Unsupported format. Use pdf, md, json or csv.");
        };
    }

    private static ResponseEntity<byte[]> download(String fileName, MediaType type, byte[] body) {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                .contentType(type)
                .body(body);
    }

    private static ResponseEntity<byte[]> error(int status, String message) {
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body(("{\"error\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8));
    }

    /** The caller's session id, or null if they have not uploaded anything (no session is created). */
    private static String sessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? null : session.getId();
    }
}
