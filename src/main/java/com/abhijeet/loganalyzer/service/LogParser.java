package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses raw log text into structured events.
 *
 * Supported formats:
 *   - Apache / Nginx "combined" access logs
 *   - SSH auth logs (sshd, syslog timestamps)
 *   - JSON lines, one object per line (common field names from nginx, Caddy, app loggers)
 *
 * Anything unrecognised still produces a LogEvent carrying the raw line, so
 * no evidence is silently discarded.
 */
@Service
public class LogParser {

    /** Apache/Nginx combined log format. */
    private static final Pattern COMBINED = Pattern.compile(
            "^(\\S+) \\S+ \\S+ \\[([^\\]]+)] \"(\\S+) (\\S+)[^\"]*\" (\\d{3}) (\\S+)(?: \"([^\"]*)\" \"([^\"]*)\")?.*$");

    /** First IPv4 address anywhere in the line - used as a fallback. */
    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b");

    /** Syslog time without a year, for example "Nov 12 03:20:11". */
    private static final Pattern SYSLOG_TIME = Pattern.compile(
            "^([A-Z][a-z]{2})\\s+(\\d{1,2})\\s+(\\d{2}):(\\d{2}):(\\d{2})\\b");

    /** Year inside an Apache time or an ISO date, used to date syslog lines. */
    private static final Pattern YEAR_HINT = Pattern.compile(
            "\\[\\d{2}/[A-Za-z]{3}/(\\d{4}):|\\b(20\\d{2})-\\d{2}-\\d{2}T");

    /** "Failed password for [invalid user] NAME from" and "Accepted publickey for NAME from". */
    private static final Pattern AUTH_USER = Pattern.compile(
            "(?i)(?:failed|accepted) \\S+ for (?:invalid user )?(\\S+) from ");

    private static final Pattern INVALID_USER = Pattern.compile("(?i)invalid user (\\S+) from ");

    private static final DateTimeFormatter APACHE_TIME =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    private static final List<String> MONTHS = List.of(
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec");

    private static final String[] AUTH_FAILURE_MARKERS = {
            "failed password", "failed publickey", "invalid user",
            "authentication failure", "failed login", "access denied"
    };

    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();

    public LogParser() {
        this(Clock.systemUTC());
    }

    public LogParser(Clock clock) {
        this.clock = clock;
    }

    public List<LogEvent> parse(String content) {
        List<LogEvent> events = new ArrayList<>();
        if (content == null || content.isBlank()) {
            return events;
        }

        String[] lines = content.split("\\R");
        int year = referenceYear(lines);

        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            events.add(parseLine(line.strip(), year));
        }
        return events;
    }

    /**
     * Syslog lines carry no year. Take it from the first dated line in the same file so that a
     * mixed file stays consistent, and fall back to the current year.
     */
    private int referenceYear(String[] lines) {
        for (String line : lines) {
            Matcher m = YEAR_HINT.matcher(line);
            if (m.find()) {
                String year = m.group(1) != null ? m.group(1) : m.group(2);
                return Integer.parseInt(year);
            }
        }
        return LocalDateTime.now(clock).getYear();
    }

    private LogEvent parseLine(String line, int year) {
        if (line.startsWith("{") && line.endsWith("}")) {
            LogEvent json = parseJson(line);
            if (json != null) {
                return json;
            }
        }

        Matcher web = COMBINED.matcher(line);
        if (web.matches()) {
            Integer status = null;
            try {
                status = Integer.valueOf(web.group(5));
            } catch (NumberFormatException ignored) {
                // keep null rather than fail the whole parse
            }
            return new LogEvent(
                    web.group(1),
                    web.group(3),
                    web.group(4),
                    status,
                    web.group(8),
                    false,
                    line,
                    apacheTime(web.group(2)),
                    null);
        }

        Matcher ip = IPV4.matcher(line);
        String address = ip.find() ? ip.group(1) : null;

        return new LogEvent(address, null, null, null, null, hasFailureMarker(line),
                line, syslogTime(line, year), authUser(line));
    }

    // ------------------------------------------------------------------- JSON

    private LogEvent parseJson(String line) {
        try {
            JsonNode node = mapper.readTree(line);
            if (node == null || !node.isObject()) {
                return null;
            }

            String ip = text(node, "remote_addr", "remote_ip", "client_ip", "clientip",
                    "ip", "src_ip", "source_ip");
            String method = text(node, "method", "request_method", "http_method");
            String path = text(node, "path", "uri", "request_uri", "url");

            String request = text(node, "request");
            if (request != null && (method == null || path == null)) {
                String[] parts = request.split(" ");
                if (parts.length >= 2) {
                    method = method == null ? parts[0] : method;
                    path = path == null ? parts[1] : path;
                }
            }

            Integer status = integer(node, "status", "status_code", "response_code");
            String userAgent = text(node, "user_agent", "http_user_agent", "useragent", "ua");
            String user = text(node, "user", "username", "user_name");
            Instant when = instant(text(node, "time", "timestamp", "@timestamp", "ts",
                    "time_iso8601", "datetime"));

            if (ip == null) {
                Matcher m = IPV4.matcher(line);
                ip = m.find() ? m.group(1) : null;
            }

            return new LogEvent(ip, method, path, status, userAgent,
                    hasFailureMarker(line), line, when, user);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    private static String text(JsonNode node, String... keys) {
        for (String key : keys) {
            JsonNode value = node.get(key);
            if (value != null && !value.isNull() && !value.isContainerNode()) {
                String text = value.asText();
                if (!text.isBlank()) {
                    return text;
                }
            }
        }
        return null;
    }

    private static Integer integer(JsonNode node, String... keys) {
        for (String key : keys) {
            JsonNode value = node.get(key);
            if (value == null || value.isNull()) {
                continue;
            }
            if (value.isNumber()) {
                return value.asInt();
            }
            try {
                return Integer.valueOf(value.asText().trim());
            } catch (NumberFormatException ignored) {
                // try the next key
            }
        }
        return null;
    }

    // ------------------------------------------------------------------- time

    private static Instant apacheTime(String value) {
        try {
            return OffsetDateTime.parse(value, APACHE_TIME).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static Instant syslogTime(String line, int year) {
        Matcher m = SYSLOG_TIME.matcher(line);
        if (!m.find()) {
            return null;
        }
        int month = MONTHS.indexOf(m.group(1).toLowerCase(Locale.ROOT)) + 1;
        if (month == 0) {
            return null;
        }
        try {
            return LocalDateTime.of(year, month, Integer.parseInt(m.group(2)),
                    Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)),
                    Integer.parseInt(m.group(5))).toInstant(ZoneOffset.UTC);
        } catch (DateTimeException e) {
            return null;
        }
    }

    private static Instant instant(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        try {
            return Instant.parse(v);
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        try {
            return OffsetDateTime.parse(v).toInstant();
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        try {
            return OffsetDateTime.parse(v, APACHE_TIME).toInstant();
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        try {
            double number = Double.parseDouble(v);
            long whole = (long) number;
            return whole > 100_000_000_000L ? Instant.ofEpochMilli(whole) : Instant.ofEpochSecond(whole);
        } catch (NumberFormatException | DateTimeException ignored) {
            return null;
        }
    }

    // ------------------------------------------------------------------- auth

    private static boolean hasFailureMarker(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        for (String marker : AUTH_FAILURE_MARKERS) {
            if (lower.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private static String authUser(String line) {
        Matcher m = AUTH_USER.matcher(line);
        if (m.find()) {
            return m.group(1);
        }
        Matcher invalid = INVALID_USER.matcher(line);
        return invalid.find() ? invalid.group(1) : null;
    }
}
