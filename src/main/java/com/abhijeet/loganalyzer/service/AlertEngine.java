package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Alert;
import com.abhijeet.loganalyzer.model.AlertRule;
import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Evaluates alert rules over the parsed events with a sliding time window. Deterministic and
 * free of I/O, so it is tested directly.
 */
public final class AlertEngine {

    static final int MAX_ALERTS = 50;
    static final int MAX_PER_RULE = 10;

    private AlertEngine() {
    }

    public static List<Alert> evaluate(List<LogEvent> events, List<Finding> findings, int riskScore,
                                       List<AlertRule> rules) {
        List<Alert> alerts = new ArrayList<>();
        for (AlertRule rule : rules) {
            switch (rule.metric()) {
                case "risk_score" -> {
                    if (rule.exceeded(riskScore)) {
                        alerts.add(alert(rule, "all", riskScore, null, "Risk score " + riskScore
                                + " (rule: " + limit(rule) + ")"));
                    }
                }
                case "finding" -> findings.stream().filter(f -> f.rule().equals(rule.rule())).findFirst()
                        .filter(f -> rule.exceeded(f.count()))
                        .ifPresent(f -> alerts.add(alert(rule, "all", f.count(), null,
                                f.title() + " (" + f.count() + (f.count() == 1 ? " event)" : " events)"))));
                default -> alerts.addAll(windowed(rule, events));
            }
        }
        alerts.sort(Comparator.comparing((Alert a) -> a.severity().ordinal())
                .thenComparing(Comparator.comparingDouble(Alert::value).reversed()));
        return alerts.size() > MAX_ALERTS ? List.copyOf(alerts.subList(0, MAX_ALERTS)) : alerts;
    }

    private static List<Alert> windowed(AlertRule rule, List<LogEvent> events) {
        Predicate<LogEvent> matches = predicate(rule.metric());
        boolean distinctPorts = "distinct_ports".equals(rule.metric());

        Map<String, List<LogEvent>> groups = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.is("stack_frame") || e.is("caused_by") || !matches.test(e)) {
                continue;
            }
            String key = switch (rule.groupBy()) {
                case "ip" -> e.ip();
                case "user" -> e.user();
                default -> "all";
            };
            if (key != null) {
                groups.computeIfAbsent(key, k -> new ArrayList<>()).add(e);
            }
        }

        List<Alert> out = new ArrayList<>();
        for (Map.Entry<String, List<LogEvent>> group : groups.entrySet()) {
            Peak peak = rule.windowMinutes() <= 0
                    ? whole(group.getValue(), distinctPorts)
                    : sliding(group.getValue(), rule.windowMinutes() * 60L, distinctPorts);
            if (peak != null && rule.exceeded(peak.value)) {
                String scope = rule.windowMinutes() <= 0 ? "in the log"
                        : "within " + rule.windowMinutes() + (rule.windowMinutes() == 1 ? " minute" : " minutes");
                String who = "all".equals(group.getKey()) ? ""
                        : ("user".equals(rule.groupBy()) ? " by " : " from ") + group.getKey();
                out.add(alert(rule, group.getKey(), peak.value, peak.start,
                        fmt(peak.value) + " " + label(rule.metric(), peak.value) + who + " " + scope
                                + (peak.start == null ? "" : " starting " + peak.start)
                                + " (rule: " + limit(rule) + ")"));
            }
        }
        out.sort(Comparator.comparingDouble(Alert::value).reversed());
        return out.size() > MAX_PER_RULE ? out.subList(0, MAX_PER_RULE) : out;
    }

    private record Peak(double value, String start) {
    }

    private static Peak whole(List<LogEvent> events, boolean distinctPorts) {
        double value = distinctPorts
                ? events.stream().map(LogEvent::port).filter(java.util.Objects::nonNull).distinct().count()
                : events.size();
        return new Peak(value, null);
    }

    /** The largest count inside any window of the given length. Events without a time are ignored. */
    static Peak sliding(List<LogEvent> events, long windowSeconds, boolean distinctPorts) {
        List<LogEvent> timed = events.stream().filter(e -> e.timestamp() != null)
                .sorted(Comparator.comparing(LogEvent::timestamp)).toList();
        if (timed.isEmpty()) {
            return null;
        }
        Map<Integer, Integer> ports = new HashMap<>();
        int best = 0;
        Instant bestStart = null;
        int left = 0;
        for (int right = 0; right < timed.size(); right++) {
            add(ports, timed.get(right).port(), 1);
            Instant end = timed.get(right).timestamp();
            while (end.getEpochSecond() - timed.get(left).timestamp().getEpochSecond() >= windowSeconds) {
                add(ports, timed.get(left).port(), -1);
                left++;
            }
            int value = distinctPorts ? ports.size() : right - left + 1;
            if (value > best) {
                best = value;
                bestStart = timed.get(left).timestamp();
            }
        }
        return new Peak(best, bestStart == null ? null : bestStart.toString());
    }

    private static void add(Map<Integer, Integer> ports, Integer port, int delta) {
        if (port == null) {
            return;
        }
        int n = ports.getOrDefault(port, 0) + delta;
        if (n <= 0) {
            ports.remove(port);
        } else {
            ports.put(port, n);
        }
    }

    static Predicate<LogEvent> predicate(String metric) {
        return switch (metric) {
            case "failed_logins" -> LogEvent::authFailure;
            case "requests" -> e -> e.method() != null || e.status() != null;
            case "events" -> e -> true;
            case "client_errors" -> e -> e.status() != null && e.status() >= 400 && e.status() < 500;
            case "server_errors" -> e -> e.status() != null && e.status() >= 500;
            case "not_found" -> e -> e.status() != null && e.status() == 404;
            case "attack_requests" -> e -> FindingDetector.isAttackPath(e.path());
            case "app_errors" -> e -> "ERROR".equals(e.level()) || "FATAL".equals(e.level());
            case "exceptions" -> e -> e.is("exception");
            case "firewall_blocks" -> e -> e.is("firewall_block");
            case "distinct_ports" -> e -> e.port() != null;
            case "crash_loops" -> e -> e.is("crash_loop");
            case "oom_kills" -> e -> e.is("oom_kill");
            case "iam_changes" -> e -> e.is("iam_change");
            case "deleted_resources" -> e -> e.is("resource_deleted");
            case "sudo_failures" -> e -> e.is("sudo_failure") || e.is("su_failure");
            case "accounts_created" -> e -> e.is("account_created");
            default -> e -> false;
        };
    }

    private static String label(String metric, double value) {
        String label = switch (metric) {
            case "distinct_ports" -> "distinct ports";
            case "iam_changes" -> "IAM changes";
            case "oom_kills" -> "OOM kills";
            default -> metric.replace('_', ' ');
        };
        if (value == 1) {
            // "1 failed login", "1 account created": singular first word.
            int space = label.indexOf(' ');
            String first = space < 0 ? label : label.substring(0, space);
            String rest = space < 0 ? "" : label.substring(space);
            if (first.endsWith("s")) {
                label = first.substring(0, first.length() - 1) + rest;
            } else if (rest.endsWith("s")) {
                label = first + rest.substring(0, rest.length() - 1);
            }
        }
        return label;
    }

    private static String limit(AlertRule rule) {
        return ("gte".equals(rule.operator()) ? "at least " : "more than ") + fmt(rule.threshold());
    }

    private static Alert alert(AlertRule rule, String group, double value, String start, String message) {
        return new Alert(rule.id(), rule.name(), rule.severity(), group, value, rule.threshold(),
                rule.windowMinutes(), start, message);
    }

    private static String fmt(double v) {
        return v == Math.rint(v) ? String.valueOf((long) v) : String.valueOf(v);
    }
}
