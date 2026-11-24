package com.abhijeet.loganalyzer.model;

import java.time.Instant;

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
 * @param timestamp   when the event happened, if the line carried a readable time
 * @param user        account name involved in an authentication event, if present
 */
public record LogEvent(
        String ip,
        String method,
        String path,
        Integer status,
        String userAgent,
        boolean authFailure,
        String raw,
        Instant timestamp,
        String user
) {

    /** Convenience constructor for events without a timestamp or user. */
    public LogEvent(String ip, String method, String path, Integer status,
                    String userAgent, boolean authFailure, String raw) {
        this(ip, method, path, status, userAgent, authFailure, raw, null, null);
    }
}
