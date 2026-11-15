package com.abhijeet.loganalyzer.model;

import java.util.List;
import java.util.Map;

/**
 * Deterministic statistics computed locally from the log.
 *
 * The LLM only ever sees this summary, never the raw file. That keeps token
 * usage small, keeps the analysis grounded in real counts, and means a
 * multi-megabyte log can still be analysed on a free tier.
 */
public record LogSummary(
        int totalLines,
        int parsedEvents,
        Map<String, Integer> topIps,
        Map<String, Integer> statusClasses,
        Map<String, Integer> topPaths,
        Map<String, Integer> authFailuresByIp,
        Map<String, Integer> suspiciousPaths,
        List<String> signals
) {
}
