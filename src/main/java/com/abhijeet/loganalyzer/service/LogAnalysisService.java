package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogSummary;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Computes detection statistics locally, then asks the model to write the report from that summary.
 */
@Service
public class LogAnalysisService {

    private static final int TOP_N = 5;
    private static final int TOP_PATHS = 10;

    private static final int TOP_AGENTS = 5;

    private final ChatModel chatModel;
    private final FindingDetector detector = new FindingDetector();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public LogAnalysisService(ChatModel chatModel) {
        this.chatModel = chatModel;
    }

    // ------------------------------------------------------------------ stats

    public LogSummary summarize(List<LogEvent> events) {
        Map<String, Integer> ipCounts = new LinkedHashMap<>();
        Map<String, Integer> statusClasses = new LinkedHashMap<>();
        Map<String, Integer> pathCounts = new LinkedHashMap<>();
        Map<String, Integer> authFailures = new LinkedHashMap<>();
        Map<String, Integer> suspicious = new LinkedHashMap<>();
        Map<String, Integer> agentCounts = new LinkedHashMap<>();

        int parsed = 0;
        Instant firstSeen = null;
        Instant lastSeen = null;

        for (LogEvent event : events) {
            if (event.ip() != null) {
                ipCounts.merge(event.ip(), 1, Integer::sum);
                parsed++;
            }
            if (event.status() != null) {
                statusClasses.merge((event.status() / 100) + "xx", 1, Integer::sum);
            }
            if (event.path() != null) {
                pathCounts.merge(event.path(), 1, Integer::sum);
                if (isSuspicious(event.path())) {
                    suspicious.merge(event.path(), 1, Integer::sum);
                }
            }
            if (event.authFailure() && event.ip() != null) {
                authFailures.merge(event.ip(), 1, Integer::sum);
            }
            String agent = event.userAgent();
            if (agent != null && !agent.isBlank() && !"-".equals(agent)) {
                agentCounts.merge(agent, 1, Integer::sum);
            }
            Instant when = event.timestamp();
            if (when != null) {
                if (firstSeen == null || when.isBefore(firstSeen)) {
                    firstSeen = when;
                }
                if (lastSeen == null || when.isAfter(lastSeen)) {
                    lastSeen = when;
                }
            }
        }

        List<String> signals = new ArrayList<>();

        authFailures.forEach((ip, count) -> {
            if (count >= 3) {
                signals.add("Brute-force pattern: " + count
                        + " failed authentications from " + ip);
            }
        });

        suspicious.forEach((path, count) ->
                signals.add("Injection or scanning attempt " + count
                        + "x on path: " + path));

        statusClasses.forEach((type, count) -> {
            if ("5xx".equals(type) && count >= 3) {
                signals.add("Server errors: " + count + " responses in the 5xx range");
            }
        });

        int volumeThreshold = Math.max(10, events.size() / 3);
        ipCounts.forEach((ip, count) -> {
            if (count > volumeThreshold) {
                signals.add("Concentrated traffic: " + count
                        + " requests from a single address " + ip);
            }
        });

        if (events.size() > 0 && parsed == 0) {
            signals.add("No IP addresses could be parsed - the log format may be unrecognised");
        }

        List<Finding> findings = detector.detect(events);
        Timeline.Result timeline = Timeline.build(events);

        return new LogSummary(
                events.size(),
                parsed,
                top(ipCounts, TOP_N),
                statusClasses,
                top(pathCounts, TOP_PATHS),
                top(authFailures, TOP_N),
                top(suspicious, TOP_PATHS),
                signals,
                FindingDetector.riskScore(findings),
                FindingDetector.riskLevel(findings),
                findings,
                timeline.points(),
                timeline.bucketMinutes(),
                firstSeen == null ? null : firstSeen.toString(),
                lastSeen == null ? null : lastSeen.toString(),
                ipCounts.size(),
                top(agentCounts, TOP_AGENTS));
    }

    private Map<String, Integer> top(Map<String, Integer> source, int max) {
        return source.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(max)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (first, second) -> first,
                        LinkedHashMap::new));
    }

    private boolean isSuspicious(String path) {
        String p = path.toLowerCase(Locale.ROOT);
        return p.contains("../")
                || p.contains("%27")
                || p.contains("'")
                || p.contains("<script")
                || p.contains("union")
                || p.contains("/.env")
                || p.contains("/etc/passwd")
                || p.contains("wp-login")
                || p.contains("/admin")
                || p.contains("phpmyadmin")
                || p.contains("/.git");
    }

    // --------------------------------------------------------------- AI report

    public String analyze(List<LogEvent> events) {
        LogSummary summary = summarize(events);

        String prompt = """
                You are a senior security analyst reviewing server logs.

                Analyse the summary below and write a concise incident report.

                Rules:
                - Use ONLY the data provided. Never invent activity that is not in the summary.
                - If the evidence is weak, say so plainly.
                - Refer to specific IP addresses, paths and counts from the data.
                - The findings already carry a severity, a MITRE ATT&CK technique and evidence.
                  Build the report on them and do not change a severity or invent a technique.
                - Do not suggest illegal or offensive actions. Remediation must be defensive.

                Respond in markdown using exactly these sections:

                ## Executive summary
                ## Detected activity
                ## Risk level
                ## Recommended actions

                Log summary (JSON):
                %s
                """.formatted(toJson(summary.withoutTimeline()));

        return chatModel.call(prompt);
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }
}
