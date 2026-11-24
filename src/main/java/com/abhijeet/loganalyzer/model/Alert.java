package com.abhijeet.loganalyzer.model;

/**
 * An alert rule that fired.
 *
 * @param ruleId        the rule's id
 * @param name          the rule's name
 * @param severity      the rule's severity
 * @param group         the IP or user it fired for, or "all" for a global rule
 * @param value         the highest value seen
 * @param threshold     the rule's threshold
 * @param windowMinutes the rule's window, 0 for the whole log
 * @param windowStart   start of the window where the value was highest, ISO-8601, or null
 * @param message       one readable sentence
 */
public record Alert(String ruleId, String name, Severity severity, String group, double value,
                    double threshold, int windowMinutes, String windowStart, String message) {
}
