package com.abhijeet.loganalyzer.controller;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.service.LogAnalysisService;
import com.abhijeet.loganalyzer.service.LogParser;
import com.abhijeet.loganalyzer.service.LogStore;
import com.abhijeet.loganalyzer.model.LogSummary;
import com.abhijeet.loganalyzer.service.ReportExporter;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
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

    /** Upper bound on parsed lines per upload, so a few uploads cannot exhaust memory. */
    static final int MAX_LINES = 100_000;

    private final LogParser parser;
    private final LogAnalysisService analysisService;
    private final LogStore store;

    public LogController(LogParser parser, LogAnalysisService analysisService, LogStore store) {
        this.parser = parser;
        this.analysisService = analysisService;
        this.store = store;
    }

    /** Upload a log file. Parsing is deterministic - no AI call, so this is instant and free. */
    @Operation(summary = "Upload a log (Apache/Nginx, SSH auth, or JSON lines); kept private to your session")
    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> upload(@RequestParam("file") MultipartFile file,
                                                      HttpServletRequest request)
            throws IOException {

        String content = new String(file.getBytes(), StandardCharsets.UTF_8);
        List<LogEvent> events = parser.parse(content);

        if (events.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "No usable log lines found in the uploaded file."));
        }

        if (events.size() > MAX_LINES) {
            return ResponseEntity.status(413)
                    .body(Map.of("error", "Log too large. Maximum is " + MAX_LINES + " lines."));
        }

        String sessionId = request.getSession(true).getId();
        store.set(sessionId, file.getOriginalFilename(), events);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("file", store.name(sessionId));
        body.put("loaded", events.size());
        body.put("summary", analysisService.summarize(events));
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
        body.put("report", analysisService.analyze(events));
        return ResponseEntity.ok(body);
    }

    /** Downloadable report built from the deterministic findings only - no AI call, no quota used. */
    @Operation(summary = "Download the report as Markdown (format=md) or JSON (format=json)")
    @GetMapping("/export")
    public ResponseEntity<String> export(@RequestParam(defaultValue = "md") String format,
                                         HttpServletRequest request) throws JsonProcessingException {
        String sessionId = sessionId(request);
        if (store.isEmpty(sessionId)) {
            return error(404, "No log loaded. Upload a file to begin.");
        }

        LogSummary summary = analysisService.summarize(store.get(sessionId));
        String name = store.name(sessionId);

        // The download name is fixed, never taken from the uploaded file name.
        if ("md".equalsIgnoreCase(format)) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"log-analysis-report.md\"")
                    .contentType(new MediaType("text", "markdown", java.nio.charset.StandardCharsets.UTF_8))
                    .body(ReportExporter.markdown(name, summary));
        }
        if ("json".equalsIgnoreCase(format)) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"log-analysis-report.json\"")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(ReportExporter.json(name, summary));
        }
        return error(400, "Unsupported format. Use md or json.");
    }

    private static ResponseEntity<String> error(int status, String message) {
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"" + message + "\"}");
    }

    /** The caller's session id, or null if they have not uploaded anything (no session is created). */
    private static String sessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? null : session.getId();
    }
}
