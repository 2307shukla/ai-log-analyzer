package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimelineTest {

    private static LogEvent event(String time, int status, boolean authFailure) {
        return new LogEvent("1.1.1.1", "GET", "/", status, "ua", authFailure, "raw", Instant.parse(time), null);
    }

    @Test
    void logsWithoutTimestampsHaveNoTimeline() {
        Timeline.Result result = Timeline.build(List.of(
                new LogEvent("1.1.1.1", "GET", "/", 200, "ua", false, "raw")));

        assertEquals(0, result.bucketMinutes());
        assertTrue(result.points().isEmpty());
    }

    @Test
    void groupsEventsIntoBucketsAndFillsTheGaps() {
        Timeline.Result result = Timeline.build(List.of(
                event("2026-11-12T08:00:10Z", 200, false),
                event("2026-11-12T08:00:50Z", 404, false),
                event("2026-11-12T08:02:00Z", 200, true)));

        assertEquals(1, result.bucketMinutes());
        assertEquals(3, result.points().size());
        assertEquals("2026-11-12T08:00:00Z", result.points().get(0).start());
        assertEquals(2, result.points().get(0).requests());
        assertEquals(1, result.points().get(0).errors());
        assertEquals(0, result.points().get(1).requests());
        assertEquals(1, result.points().get(2).requests());
        assertEquals(1, result.points().get(2).errors());
    }

    @Test
    void bucketSizeGrowsWithTheTimeSpanAndStaysReadable() {
        assertEquals(1, Timeline.chooseBucket(60));
        assertEquals(5, Timeline.chooseBucket(200));
        assertEquals(60, Timeline.chooseBucket(24 * 60));
        assertEquals(1440, Timeline.chooseBucket(100_000));

        long huge = 10_000_000L;
        assertTrue(huge / Timeline.chooseBucket(huge) < Timeline.MAX_POINTS);
    }
}
