package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    private static LogEvent at(String time, Integer status, boolean authFailure, String level, String category) {
        return new LogEvent("1.1.1.1", status == null ? null : "GET", "/", status, "ua", authFailure, "raw",
                Instant.parse(time), null, com.abhijeet.loganalyzer.model.LogFormat.UNKNOWN, level, category, null, null);
    }

    @Test
    void breaksErrorsDownByType() {
        Timeline.Result r = Timeline.build(List.of(
                at("2026-11-12T08:00:01Z", 404, false, null, null),
                at("2026-11-12T08:00:02Z", 503, false, null, null),
                at("2026-11-12T08:00:03Z", null, true, null, "logon_failure"),
                at("2026-11-12T08:00:04Z", null, false, "ERROR", "app_error"),
                at("2026-11-12T08:00:05Z", null, false, null, "stack_frame"),
                at("2026-11-12T08:00:06Z", 200, false, null, null)), 1);

        assertEquals(1, r.points().size());
        var p = r.points().get(0);
        assertEquals(5, p.requests(), "stack frames are not events of their own");
        assertEquals(1, p.clientErrors());
        assertEquals(1, p.serverErrors());
        assertEquals(1, p.authFailures());
        assertEquals(1, p.appErrors());
        assertEquals(4, p.errors());
    }

    @Test
    void flagsSpikesAgainstTheTypicalBucket() {
        List<LogEvent> events = new java.util.ArrayList<>();
        for (int m = 0; m < 10; m++) {
            events.add(at(String.format("2026-11-12T08:%02d:00Z", m), 200, false, null, null));
            events.add(at(String.format("2026-11-12T08:%02d:30Z", m), 200, false, null, null));
        }
        for (int i = 0; i < 12; i++) {
            events.add(at(String.format("2026-11-12T08:05:%02dZ", i), 500, false, null, null));
        }
        Timeline.Result r = Timeline.build(events, 1);

        assertTrue(r.points().get(5).spike());
        assertTrue(r.points().get(5).errorSpike());
        assertFalse(r.points().get(4).spike());
        assertFalse(r.points().get(4).errorSpike());
    }

    @Test
    void smallBucketsAreNeverSpikes() {
        Timeline.Result r = Timeline.build(List.of(
                at("2026-11-12T08:00:00Z", 200, false, null, null),
                at("2026-11-12T08:05:00Z", 200, false, null, null),
                at("2026-11-12T08:05:01Z", 200, false, null, null),
                at("2026-11-12T08:05:02Z", 200, false, null, null)), 1);
        assertTrue(r.points().stream().noneMatch(p -> p.spike()));
    }

    @Test
    void explicitHourlyBucketsAndALimitOnPerMinuteViews() {
        List<LogEvent> twoDays = List.of(
                at("2026-11-12T00:00:00Z", 200, false, null, null),
                at("2026-11-13T23:59:00Z", 200, false, null, null));
        assertEquals(48, Timeline.build(twoDays, 60).points().size());
        assertThrows(Timeline.TooManyPointsException.class, () -> Timeline.build(twoDays, 1));
    }
}
