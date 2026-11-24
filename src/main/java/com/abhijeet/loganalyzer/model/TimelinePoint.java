package com.abhijeet.loganalyzer.model;

/**
 * Events seen in one time bucket.
 *
 * @param start        start of the bucket, ISO-8601 in UTC
 * @param requests     events in the bucket (requests for web logs, entries for other logs)
 * @param errors       all error-type events: the sum of the four breakdown counts below
 * @param clientErrors HTTP 4xx responses
 * @param serverErrors HTTP 5xx responses
 * @param authFailures failed logins (SSH, Windows, cloud console, sudo/su)
 * @param appErrors    application errors: ERROR/FATAL lines, exceptions, crashes, OOM kills, blocked connections
 * @param spike        true when the bucket's volume is far above the typical bucket
 * @param errorSpike   true when the bucket's errors are far above the typical bucket
 */
public record TimelinePoint(String start, int requests, int errors, int clientErrors, int serverErrors,
                            int authFailures, int appErrors, boolean spike, boolean errorSpike) {

    /** A bucket with totals only, no breakdown. */
    public TimelinePoint(String start, int requests, int errors) {
        this(start, requests, errors, 0, 0, 0, 0, false, false);
    }
}
