package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.TimelinePoint;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Groups events into equal time buckets for the request and error charts. In automatic mode the
 * bucket size is chosen from the time span so the chart always has a readable number of bars;
 * per-minute and per-hour views can also be asked for explicitly.
 */
public final class Timeline {

    static final int MAX_POINTS = 96;
    /** Upper bound for an explicit per-minute or per-hour view (one day of minutes). */
    public static final int MAX_EXPLICIT_POINTS = 1440;
    private static final int[] BUCKET_MINUTES = {1, 5, 15, 60, 360, 1440};

    /** A bucket is a spike when it is at least this many times the median non-empty bucket ... */
    static final int SPIKE_FACTOR = 3;
    /** ... and at least this large, so a quiet log does not show spikes of three events. */
    static final int SPIKE_MIN_REQUESTS = 10;
    static final int SPIKE_MIN_ERRORS = 5;

    private static final List<String> APP_ERROR_CATEGORIES = List.of(
            "app_error", "exception", "crash_loop", "oom_kill", "probe_failed", "image_pull_error",
            "firewall_block");

    private Timeline() {
    }

    /** Result of {@link #build}; bucketMinutes is 0 when no event carried a timestamp. */
    public record Result(int bucketMinutes, List<TimelinePoint> points) {
    }

    /** Thrown when an explicit bucket size would need more than {@link #MAX_EXPLICIT_POINTS} bars. */
    public static class TooManyPointsException extends RuntimeException {
        public TooManyPointsException(long points) {
            super("That view would need " + points + " bars. Use a larger bucket (hour) for this log.");
        }
    }

    /** Automatic bucket size. */
    public static Result build(List<LogEvent> events) {
        return build(events, 0);
    }

    /**
     * @param bucketMinutes bucket size, or 0 to choose one from the time span
     */
    public static Result build(List<LogEvent> events, int bucketMinutes) {
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
        int bucket = bucketMinutes > 0 ? bucketMinutes : chooseBucket(spanMinutes);
        long bucketSeconds = bucket * 60L;
        long first = Math.floorDiv(min.getEpochSecond(), bucketSeconds);
        long last = Math.floorDiv(max.getEpochSecond(), bucketSeconds);
        long count = last - first + 1;
        if (bucketMinutes > 0 && count > MAX_EXPLICIT_POINTS) {
            throw new TooManyPointsException(count);
        }
        int size = (int) count;

        int[] requests = new int[size];
        int[] client = new int[size];
        int[] server = new int[size];
        int[] auth = new int[size];
        int[] app = new int[size];
        for (LogEvent e : events) {
            Instant t = e.timestamp();
            // Stack-trace lines belong to the log line above them and are not events of their own.
            if (t == null || e.is("stack_frame") || e.is("caused_by")) {
                continue;
            }
            int i = (int) (Math.floorDiv(t.getEpochSecond(), bucketSeconds) - first);
            requests[i]++;
            if (e.authFailure()) {
                auth[i]++;
            } else if (e.status() != null && e.status() >= 500) {
                server[i]++;
            } else if (e.status() != null && e.status() >= 400) {
                client[i]++;
            } else if (isAppError(e)) {
                app[i]++;
            }
        }

        int[] errors = new int[size];
        for (int i = 0; i < size; i++) {
            errors[i] = client[i] + server[i] + auth[i] + app[i];
        }
        // Volume is compared with the usual non-empty bucket; errors with the usual bucket overall,
        // which is often zero, so a lone burst of errors still stands out.
        int typicalRequests = median(requests);
        int typicalErrors = medianAll(errors);

        List<TimelinePoint> points = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            boolean spike = requests[i] >= SPIKE_MIN_REQUESTS && requests[i] >= SPIKE_FACTOR * typicalRequests;
            boolean errorSpike = errors[i] >= SPIKE_MIN_ERRORS && errors[i] >= SPIKE_FACTOR * typicalErrors;
            points.add(new TimelinePoint(Instant.ofEpochSecond((first + i) * bucketSeconds).toString(),
                    requests[i], errors[i], client[i], server[i], auth[i], app[i], spike, errorSpike));
        }
        return new Result(bucket, points);
    }

    private static boolean isAppError(LogEvent e) {
        return "ERROR".equals(e.level()) || "FATAL".equals(e.level())
                || (e.category() != null && APP_ERROR_CATEGORIES.contains(e.category()));
    }

    /** Median of the non-empty buckets (lower median), 0 when all are empty. */
    static int median(int[] values) {
        int[] nonZero = Arrays.stream(values).filter(v -> v > 0).sorted().toArray();
        return nonZero.length == 0 ? 0 : nonZero[(nonZero.length - 1) / 2];
    }

    static int medianAll(int[] values) {
        int[] sorted = Arrays.stream(values).sorted().toArray();
        return sorted.length == 0 ? 0 : sorted[(sorted.length - 1) / 2];
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
