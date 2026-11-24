package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Holds loaded logs in memory.
 *
 * Each visitor's upload is kept under their own session id, so one person's
 * file is never shown to, or overwritten by, another visitor. Visitors who
 * have not uploaded anything see the bundled sample log.
 *
 * Memory is bounded: only the most recently used {@value #MAX_SESSIONS}
 * uploads are kept, and older ones are evicted.
 */
@Service
public class LogStore {

    static final int MAX_SESSIONS = 4;

    private record Entry(String name, List<LogEvent> events) {
    }

    private static final Entry EMPTY = new Entry("none", List.of());

    private volatile Entry sample = EMPTY;

    private final Map<String, Entry> bySession = Collections.synchronizedMap(
            new LinkedHashMap<>(8, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
                    return size() > MAX_SESSIONS;
                }
            });

    /** The bundled sample, shown to visitors who have not uploaded a file. */
    public void setSample(String name, List<LogEvent> events) {
        this.sample = new Entry(name, List.copyOf(events));
    }

    /** Stores a visitor's upload under their session id. */
    public void set(String sessionId, String name, List<LogEvent> events) {
        bySession.put(sessionId, new Entry(name == null ? "upload" : name, List.copyOf(events)));
    }

    public List<LogEvent> get(String sessionId) {
        return entry(sessionId).events();
    }

    public String name(String sessionId) {
        return entry(sessionId).name();
    }

    public boolean isEmpty(String sessionId) {
        return entry(sessionId).events().isEmpty();
    }

    private Entry entry(String sessionId) {
        if (sessionId != null) {
            Entry own = bySession.get(sessionId);
            if (own != null) {
                return own;
            }
        }
        return sample;
    }
}
