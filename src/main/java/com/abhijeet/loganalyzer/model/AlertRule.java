package com.abhijeet.loganalyzer.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A user-configurable alert, loaded from alert-rules.yml (or a JSON/YAML file named by ALERT_RULES_FILE).
 * The alert fires when the metric, counted per group inside any window of {@code windowMinutes},
 * is greater than {@code threshold} (or greater-or-equal with operator "gte").
 *
 * @param id            unique id, letters, digits, dash and underscore
 * @param name          what the alert means, shown in the UI
 * @param metric        one of {@link #METRICS}
 * @param groupBy       ip, user or global
 * @param threshold     the limit; "more than 5" is threshold 5
 * @param operator      gt (default) or gte
 * @param windowMinutes sliding window; 0 counts the whole log
 * @param severity      low, medium, high or critical
 * @param rule          for metric "finding": the finding rule id to watch, for example COMPROMISED_LOGIN
 */
public record AlertRule(String id, String name, String metric, String groupBy, double threshold,
                        String operator, int windowMinutes, Severity severity, String rule) {

    public static final List<String> METRICS = List.of(
            "failed_logins", "requests", "events", "client_errors", "server_errors", "not_found",
            "attack_requests", "app_errors", "exceptions", "firewall_blocks", "distinct_ports",
            "crash_loops", "oom_kills", "iam_changes", "deleted_resources", "sudo_failures",
            "accounts_created", "risk_score", "finding");

    public static final List<String> GROUPS = List.of("ip", "user", "global");

    /** Builds a rule from a parsed YAML/JSON object, adding any problems to {@code errors}. */
    public static AlertRule fromMap(Map<?, ?> map, int index, List<String> errors) {
        List<String> problems = new ArrayList<>();
        String id = text(map.get("id"));
        String where = "rule " + (id == null ? "#" + (index + 1) : "'" + id + "'");
        if (id == null || !id.matches("[A-Za-z0-9_-]{1,40}")) {
            problems.add("id is required (letters, digits, - and _, at most 40)");
        }
        String name = text(map.get("name"));
        if (name == null || name.length() > 120) {
            problems.add("name is required (at most 120 characters)");
        }
        String metric = lower(map.get("metric"));
        if (metric == null || !METRICS.contains(metric)) {
            problems.add("metric must be one of " + METRICS);
        }
        String groupBy = lower(map.get("groupBy"));
        groupBy = groupBy == null ? "global" : groupBy;
        if (!GROUPS.contains(groupBy)) {
            problems.add("groupBy must be ip, user or global");
        }
        Double threshold = number(map.get("threshold"));
        if (threshold == null || threshold < 0 || threshold > 1_000_000) {
            problems.add("threshold must be a number from 0 to 1000000");
        }
        String operator = lower(map.get("operator"));
        operator = operator == null ? "gt" : operator;
        if (!operator.equals("gt") && !operator.equals("gte")) {
            problems.add("operator must be gt or gte");
        }
        Double window = number(map.get("windowMinutes"));
        int windowMinutes = window == null ? 0 : (int) Math.round(window);
        if (window != null && (window < 0 || window > 10_080)) {
            problems.add("windowMinutes must be from 0 to 10080 (one week)");
        }
        Severity severity = null;
        String sev = lower(map.get("severity"));
        try {
            severity = Severity.valueOf((sev == null ? "medium" : sev).toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            problems.add("severity must be low, medium, high or critical");
        }
        String rule = text(map.get("rule"));
        if ("finding".equals(metric) && (rule == null || !rule.matches("[A-Z_]{2,40}"))) {
            problems.add("metric finding needs rule, for example COMPROMISED_LOGIN");
        }
        Object enabled = map.get("enabled");
        if (enabled != null && !(enabled instanceof Boolean)) {
            problems.add("enabled must be true or false");
        }
        if (!problems.isEmpty()) {
            problems.forEach(p -> errors.add(where + ": " + p));
            return null;
        }
        if (Boolean.FALSE.equals(enabled)) {
            return null;
        }
        return new AlertRule(id, name, metric, groupBy, threshold, operator, windowMinutes, severity, rule);
    }

    public boolean exceeded(double value) {
        return "gte".equals(operator) ? value >= threshold : value > threshold;
    }

    private static String text(Object value) {
        return value == null || String.valueOf(value).isBlank() ? null : String.valueOf(value).strip();
    }

    private static String lower(Object value) {
        String t = text(value);
        return t == null ? null : t.toLowerCase(Locale.ROOT);
    }

    private static Double number(Object value) {
        if (value instanceof Number n) {
            return n.doubleValue();
        }
        try {
            return value == null ? null : Double.valueOf(String.valueOf(value).strip());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
