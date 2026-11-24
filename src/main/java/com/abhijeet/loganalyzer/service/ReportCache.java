package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Remembers the last AI incident report per visitor so exports can include it without a second
 * model call. A report is only returned for the exact log it was written for: loading another log
 * makes it stale. Bounded like the log store.
 */
@Service
public class ReportCache {

    static final int MAX_ENTRIES = 50;
    static final String SAMPLE_KEY = "\u0000sample";

    private record Entry(List<LogEvent> events, String report) {
    }

    private final Map<String, Entry> entries = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    public void put(String sessionId, List<LogEvent> events, String report) {
        entries.put(key(sessionId), new Entry(events, report));
    }

    /** The report written for exactly these events, or null. */
    public String get(String sessionId, List<LogEvent> events) {
        Entry e = entries.get(key(sessionId));
        return e != null && e.events() == events ? e.report() : null;
    }

    private static String key(String sessionId) {
        return sessionId == null ? SAMPLE_KEY : sessionId;
    }
}
