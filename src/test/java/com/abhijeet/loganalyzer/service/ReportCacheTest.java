package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ReportCacheTest {

    private static List<LogEvent> log() {
        return List.of(new LogEvent("1.1.1.1", "GET", "/", 200, "ua", false, "raw"));
    }

    @Test
    void returnsTheReportOnlyForTheSameLog() {
        ReportCache cache = new ReportCache();
        List<LogEvent> first = log();
        cache.put("s1", first, "report one");

        assertEquals("report one", cache.get("s1", first));
        assertNull(cache.get("s1", log()), "another upload, even with equal content, makes it stale");
        assertNull(cache.get("s2", first), "never shared between visitors");
    }

    @Test
    void visitorsWithoutASessionShareTheSampleReport() {
        ReportCache cache = new ReportCache();
        List<LogEvent> sample = log();
        cache.put(null, sample, "sample report");
        assertEquals("sample report", cache.get(null, sample));
    }

    @Test
    void isBounded() {
        ReportCache cache = new ReportCache();
        List<LogEvent> events = log();
        for (int i = 0; i <= ReportCache.MAX_ENTRIES; i++) {
            cache.put("s" + i, events, "r" + i);
        }
        assertNull(cache.get("s0", events));
        assertEquals("r" + ReportCache.MAX_ENTRIES, cache.get("s" + ReportCache.MAX_ENTRIES, events));
    }
}
