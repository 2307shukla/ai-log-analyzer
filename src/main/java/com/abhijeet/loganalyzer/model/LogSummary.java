package com.abhijeet.loganalyzer.model;

import java.util.List;
import java.util.Map;

/**
 * Deterministic statistics and findings computed locally from the log.
 *
 * The LLM only ever sees this summary, never the raw file. That keeps token
 * usage small, keeps the analysis grounded in real counts, and means a
 * multi-megabyte log can still be analysed on a free tier.
 *
 * @param riskScore             0 to 100, derived from the severity of the findings
 * @param riskLevel             CLEAN, LOW, MEDIUM, HIGH or CRITICAL
 * @param findings              detected issues, most serious first
 * @param timeline              requests per time bucket, empty when the log has no timestamps
 * @param timelineBucketMinutes size of each timeline bucket, in minutes
 * @param firstSeen             earliest timestamp in the log, ISO-8601 UTC, or null
 * @param lastSeen              latest timestamp in the log, ISO-8601 UTC, or null
 * @param uniqueIps             number of distinct source addresses
 * @param topUserAgents         most common user agents
 * @param formats               recognised lines per detected format, most common first
 * @param detectedFormat        the dominant format, or "Mixed: A, B" when no format dominates
 * @param suspiciousIps         top offenders, highest score first, with GeoIP when available
 * @param geoipSource           the GeoIP database in use, or null when GeoIP is unavailable
 * @param alerts                alert rules that fired, most severe first
 */
public record LogSummary(
        int totalLines,
        int parsedEvents,
        Map<String, Integer> topIps,
        Map<String, Integer> statusClasses,
        Map<String, Integer> topPaths,
        Map<String, Integer> authFailuresByIp,
        Map<String, Integer> suspiciousPaths,
        List<String> signals,
        int riskScore,
        String riskLevel,
        List<Finding> findings,
        List<TimelinePoint> timeline,
        int timelineBucketMinutes,
        String firstSeen,
        String lastSeen,
        int uniqueIps,
        Map<String, Integer> topUserAgents,
        Map<String, Integer> formats,
        String detectedFormat,
        List<SuspiciousIp> suspiciousIps,
        String geoipSource,
        List<Alert> alerts
) {

    /** Same summary without the timeline, used for the AI prompt to keep it small. */
    public LogSummary withoutTimeline() {
        return new LogSummary(totalLines, parsedEvents, topIps, statusClasses, topPaths,
                authFailuresByIp, suspiciousPaths, signals, riskScore, riskLevel, findings,
                List.of(), timelineBucketMinutes, firstSeen, lastSeen, uniqueIps, topUserAgents, formats, detectedFormat, suspiciousIps, geoipSource, alerts);
    }
}
