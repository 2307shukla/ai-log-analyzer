package com.abhijeet.loganalyzer.model;

/**
 * One parsed log line. Fields are nullable because a line may only partially
 * match a known format - we never drop a line, we degrade gracefully.
 *
 * @param ip          source address, if one could be identified
 * @param method      HTTP method (web logs only)
 * @param path        requested path (web logs only)
 * @param status      HTTP status code (web logs only)
 * @param userAgent   client user agent (web logs only)
 * @param authFailure true when the line records a failed authentication
 * @param raw         the original line, always preserved
 */
public record LogEvent(
        String ip,
        String method,
        String path,
        Integer status,
        String userAgent,
        boolean authFailure,
        String raw
) {
}
