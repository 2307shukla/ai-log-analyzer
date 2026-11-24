package com.abhijeet.loganalyzer.model;

/**
 * Requests seen in one time bucket.
 *
 * @param start    start of the bucket, ISO-8601 in UTC
 * @param requests number of events in the bucket
 * @param errors   events that were client or server errors, or failed authentications
 */
public record TimelinePoint(String start, int requests, int errors) {
}
