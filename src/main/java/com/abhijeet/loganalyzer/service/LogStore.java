package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Holds the currently loaded log in memory.
 *
 * Deliberately simple: this is a demo project, and an in-memory store means
 * zero database cost. It is also the main limitation - see the README.
 */
@Service
public class LogStore {

    private volatile List<LogEvent> events = List.of();
    private volatile String name = "none";

    public void set(String name, List<LogEvent> events) {
        this.name = name == null ? "upload" : name;
        this.events = List.copyOf(events);
    }

    public List<LogEvent> get() {
        return events;
    }

    public String name() {
        return name;
    }

    public boolean isEmpty() {
        return events.isEmpty();
    }
}
