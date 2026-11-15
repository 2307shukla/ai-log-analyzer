package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses raw log text into structured events.
 *
 * Supports the two formats most people actually have:
 *   - Apache / Nginx "combined" access logs
 *   - SSH auth logs (sshd)
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

    private static final String[] AUTH_FAILURE_MARKERS = {
            "failed password", "failed publickey", "invalid user",
            "authentication failure", "failed login", "access denied"
    };

    public List<LogEvent> parse(String content) {
        List<LogEvent> events = new ArrayList<>();
        if (content == null || content.isBlank()) {
            return events;
        }

        for (String line : content.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            events.add(parseLine(line.strip()));
        }
        return events;
    }

    private LogEvent parseLine(String line) {
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
                    line);
        }

        String lower = line.toLowerCase(Locale.ROOT);
        boolean authFailure = false;
        for (String marker : AUTH_FAILURE_MARKERS) {
            if (lower.contains(marker)) {
                authFailure = true;
                break;
            }
        }

        Matcher ip = IPV4.matcher(line);
        String address = ip.find() ? ip.group(1) : null;

        return new LogEvent(address, null, null, null, null, authFailure, line);
    }
}
