package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.TimelinePoint;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Groups events into equal time buckets for the request-rate chart. The bucket size is chosen
 * from the time span so the chart always has a readable number of bars.
 */
public final class Timeline {

    static final int MAX_POINTS = 96;
    private static final int[] BUCKET_MINUTES = {1, 5, 15, 60, 360, 1440};

    private Timeline() {
    }

    /** Result of {@link #build}; bucketMinutes is 0 when no event carried a timestamp. */
    public record Result(int bucketMinutes, List<TimelinePoint> points) {
    }

    public static Result build(List<LogEvent> events) {
        Instant min = null;
        Instant max = null;
        for (LogEvent e : events) {
            Instant t = e.timestamp();
            if (t == null) {
                continue;
            }
            if (min == null || t.isBefore(min)) {
                min = t;
            }
            if (max == null || t.isAfter(max)) {
                max = t;
            }
        }
        if (min == null) {
            return new Result(0, List.of());
        }

        long spanMinutes = (max.getEpochSecond() - min.getEpochSecond()) / 60;
        int bucket = chooseBucket(spanMinutes);
        long bucketSeconds = bucket * 60L;
        long first = Math.floorDiv(min.getEpochSecond(), bucketSeconds);
        long last = Math.floorDiv(max.getEpochSecond(), bucketSeconds);
        int size = (int) (last - first + 1);

        int[] requests = new int[size];
        int[] errors = new int[size];
        for (LogEvent e : events) {
            Instant t = e.timestamp();
            if (t == null) {
                continue;
            }
            int index = (int) (Math.floorDiv(t.getEpochSecond(), bucketSeconds) - first);
            requests[index]++;
            if (e.authFailure() || (e.status() != null && e.status() >= 400)) {
                errors[index]++;
            }
        }

        List<TimelinePoint> points = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            points.add(new TimelinePoint(
                    Instant.ofEpochSecond((first + i) * bucketSeconds).toString(), requests[i], errors[i]));
        }
        return new Result(bucket, points);
    }

    static int chooseBucket(long spanMinutes) {
        for (int minutes : BUCKET_MINUTES) {
            if (spanMinutes / minutes < MAX_POINTS) {
                return minutes;
            }
        }
        // Very long spans: whole days, widened so the chart never exceeds MAX_POINTS bars.
        long widened = (long) Math.ceil(spanMinutes / (double) MAX_POINTS / 1440d) * 1440L;
        return (int) Math.max(1440L, Math.min(widened, Integer.MAX_VALUE));
    }
}
