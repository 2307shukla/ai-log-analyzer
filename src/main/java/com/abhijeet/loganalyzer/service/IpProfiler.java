package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.GeoLocation;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.Severity;
import com.abhijeet.loganalyzer.model.SuspiciousIp;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Scores every source address from what it did, deterministically, and returns the worst
 * offenders. Points (capped at 100):
 *
 * <ul>
 *   <li>logged in after 3+ failures: +40</li>
 *   <li>3+ failed logins: 10 + one per failure (max +30)</li>
 *   <li>injection, XSS or traversal requests: 15 + three per request (max +30)</li>
 *   <li>stopped or deleted cloud logging: +30; deleted cloud resources or changed IAM: +10 each</li>
 *   <li>probed 10+ ports: +25; firewall blocks (5+): one per two blocks (max +10)</li>
 *   <li>known scanner user agent: +15</li>
 *   <li>sensitive-path probes: 5 + one per probe (max +15)</li>
 *   <li>10+ distinct missing pages: +10; triggered 3+ server errors: +5</li>
 * </ul>
 *
 * The severity uses the same bands as the overall risk: 70+ CRITICAL, 40+ HIGH, 15+ MEDIUM, else LOW.
 */
public final class IpProfiler {

    public static final int TOP = 10;

    private IpProfiler() {
    }

    private static final class Profile {
        int events;
        int failures;
        boolean successAfterFailures;
        int failuresBeforeSuccess;
        int attacks;
        int probes;
        int blocked;
        int serverErrors;
        String scanner;
        boolean loggingDisabled;
        boolean deleted;
        boolean iam;
        final Set<Integer> ports = new HashSet<>();
        final Set<String> missing = new HashSet<>();
    }

    public static List<SuspiciousIp> profile(List<LogEvent> events, GeoLookup geo) {
        Map<String, Profile> byIp = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.ip() == null || !IpClassifier.isLiteral(e.ip())) {
                continue;
            }
            Profile p = byIp.computeIfAbsent(e.ip(), k -> new Profile());
            p.events++;
            if (e.authFailure()) {
                p.failures++;
            } else if (isSuccess(e) && p.failures >= 3 && !p.successAfterFailures) {
                p.successAfterFailures = true;
                p.failuresBeforeSuccess = p.failures;
            }
            if (FindingDetector.isAttackPath(e.path())) {
                p.attacks++;
            } else if (FindingDetector.isSensitivePath(e.path())) {
                p.probes++;
            }
            if (e.status() != null && e.status() == 404 && e.path() != null) {
                p.missing.add(e.path());
            }
            if (e.status() != null && e.status() >= 500) {
                p.serverErrors++;
            }
            if (p.scanner == null) {
                p.scanner = FindingDetector.scanner(e.userAgent());
            }
            if (e.is("firewall_block")) {
                p.blocked++;
            }
            if (e.port() != null) {
                p.ports.add(e.port());
            }
            p.loggingDisabled |= e.is("logging_disabled");
            p.deleted |= e.is("resource_deleted");
            p.iam |= e.is("iam_change");
        }

        List<SuspiciousIp> result = new ArrayList<>();
        byIp.forEach((ip, p) -> {
            List<String> reasons = new ArrayList<>();
            int score = score(p, reasons);
            if (score > 0) {
                result.add(build(ip, p, score, reasons, null));
            }
        });
        result.sort(Comparator.comparingInt(SuspiciousIp::score).reversed()
                .thenComparing(Comparator.comparingInt(SuspiciousIp::events).reversed()));

        // GeoIP only for the few addresses that are shown.
        List<SuspiciousIp> top = new ArrayList<>();
        for (SuspiciousIp s : result.subList(0, Math.min(TOP, result.size()))) {
            Optional<GeoLocation> where = geo == null ? Optional.empty() : geo.lookup(s.ip());
            top.add(where.map(g -> new SuspiciousIp(s.ip(), s.score(), s.severity(), s.events(), s.failedLogins(),
                    s.attackRequests(), s.probes(), s.blocked(), s.portsProbed(), s.reasons(), s.network(),
                    g.country(), g.countryCode(), g.city())).orElse(s));
        }
        return top;
    }

    private static int score(Profile p, List<String> reasons) {
        int score = 0;
        if (p.successAfterFailures) {
            score += 40;
            reasons.add("logged in after " + p.failuresBeforeSuccess + " failed attempts");
        }
        if (p.failures >= 3) {
            score += 10 + Math.min(20, p.failures);
            reasons.add(p.failures + " failed logins");
        }
        if (p.attacks > 0) {
            score += 15 + Math.min(15, 3 * p.attacks);
            reasons.add(p.attacks + " injection or traversal requests");
        }
        if (p.loggingDisabled) {
            score += 30;
            reasons.add("stopped or deleted cloud logging");
        }
        if (p.deleted) {
            score += 10;
            reasons.add("deleted cloud resources");
        }
        if (p.iam) {
            score += 10;
            reasons.add("changed IAM permissions");
        }
        if (p.ports.size() >= PlatformRules.PORT_SCAN_MIN_PORTS) {
            score += 25;
            reasons.add("probed " + p.ports.size() + " ports");
        }
        if (p.blocked >= 5) {
            score += Math.min(10, p.blocked / 2);
            reasons.add(p.blocked + " connections blocked by the firewall");
        }
        if (p.scanner != null) {
            score += 15;
            reasons.add("uses the scanner " + p.scanner);
        }
        if (p.probes > 0) {
            score += 5 + Math.min(10, p.probes);
            reasons.add(p.probes + " requests for sensitive paths");
        }
        if (p.missing.size() >= FindingDetector.FORCED_BROWSING_MIN) {
            score += 10;
            reasons.add(p.missing.size() + " different missing pages");
        }
        if (p.serverErrors >= 3) {
            score += 5;
            reasons.add(p.serverErrors + " requests that caused server errors");
        }
        return Math.min(100, score);
    }

    private static SuspiciousIp build(String ip, Profile p, int score, List<String> reasons, GeoLocation geo) {
        return new SuspiciousIp(ip, score, severity(score).name(), p.events, p.failures, p.attacks, p.probes,
                p.blocked, p.ports.size(), List.copyOf(reasons), IpClassifier.classify(ip),
                geo == null ? null : geo.country(), geo == null ? null : geo.countryCode(),
                geo == null ? null : geo.city());
    }

    static Severity severity(int score) {
        return score >= 70 ? Severity.CRITICAL : score >= 40 ? Severity.HIGH : score >= 15 ? Severity.MEDIUM : Severity.LOW;
    }

    private static boolean isSuccess(LogEvent e) {
        if (e.is("logon_success") || e.is("console_login") || e.is("console_login_no_mfa")) {
            return true;
        }
        String raw = e.raw() == null ? "" : e.raw().toLowerCase(java.util.Locale.ROOT);
        return raw.contains("accepted password") || raw.contains("accepted publickey");
    }
}
