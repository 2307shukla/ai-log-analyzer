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
 * @param userAgent   client user agent (web and CloudTrail logs)
 * @param authFailure true when the line records a failed authentication
 * @param raw         the original line, always preserved
 * @param timestamp   when the event happened, if the line carried a readable time
 * @param user        account name involved in the event, if present
 * @param format      which log format the line was recognised as
 * @param level       log level for application logs (ERROR, WARN, ...)
 * @param category    what the event means, for example logon_failure, iam_change, oom_kill
 * @param detail      extra context: exception class, Windows event id, CloudTrail event name,
 *                    container or pod name
 * @param port        destination port (firewall logs)
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
        String user,
        LogFormat format,
        String level,
        String category,
        String detail,
        Integer port
) {

    public LogEvent {
        format = format == null ? LogFormat.UNKNOWN : format;
    }

    /** Convenience constructor for events without a timestamp or user. */
    public LogEvent(String ip, String method, String path, Integer status,
                    String userAgent, boolean authFailure, String raw) {
        this(ip, method, path, status, userAgent, authFailure, raw, null, null);
    }

    /** Convenience constructor for events of an unspecified format. */
    public LogEvent(String ip, String method, String path, Integer status, String userAgent,
                    boolean authFailure, String raw, Instant timestamp, String user) {
        this(ip, method, path, status, userAgent, authFailure, raw, timestamp, user,
                LogFormat.UNKNOWN, null, null, null, null);
    }

    /** Same event recognised as another format, keeping a timestamp when this one has none. */
    public LogEvent as(LogFormat newFormat, Instant fallbackTime) {
        return new LogEvent(ip, method, path, status, userAgent, authFailure, raw,
                timestamp != null ? timestamp : fallbackTime, user, newFormat, level, category, detail, port);
    }

    public boolean is(String expectedCategory) {
        return expectedCategory.equals(category);
    }
}
