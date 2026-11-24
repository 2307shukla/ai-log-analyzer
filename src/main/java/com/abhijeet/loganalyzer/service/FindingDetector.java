package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.Severity;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * The detection engine. Every rule is plain Java over the parsed events, so results are
 * reproducible, free to compute and explainable: each finding carries a count, concrete
 * evidence, a MITRE ATT&CK technique where one applies, and a defensive recommendation.
 */
public class FindingDetector {

    static final int BRUTE_FORCE_MIN = 3;
    static final int SPRAYING_MIN_USERS = 5;
    static final int FORCED_BROWSING_MIN = 10;
    static final int SERVER_ERRORS_MIN = 3;
    static final int BURST_MIN_EVENTS = 30;
    static final int BURST_MIN_PEAK = 20;
    static final int BURST_MEDIAN_FACTOR = 5;

    private static final int EVIDENCE_LIMIT = 5;
    private static final int EVIDENCE_WIDTH = 120;

    private static final List<String> SCANNER_AGENTS = List.of(
            "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wpscan",
            "hydra", "acunetix", "zgrab", "nessus", "havij", "nuclei", "feroxbuster");

    private static final List<String> SENSITIVE_PATHS = List.of(
            "/.env", "/.git", "wp-login", "wp-admin", "phpmyadmin", "/admin", "/.aws",
            "/.ssh", "id_rsa", "/backup", ".sql", "/config.php", "/server-status");

    private static final List<String> SQLI = List.of(
            "'", "union select", "union all select", "select ", "sleep(", "benchmark(",
            "information_schema", "1=1");

    private static final List<String> XSS = List.of(
            "<script", "javascript:", "onerror=", "onload=", "<img", "alert(");

    private static final List<String> TRAVERSAL = List.of(
            "../", "..\\", "/etc/passwd", "/etc/shadow", "boot.ini", "win.ini");

    private static final List<String> SUCCESS_MARKERS = List.of(
            "accepted password", "accepted publickey", "accepted keyboard-interactive",
            "login successful", "successfully authenticated");

    public List<Finding> detect(List<LogEvent> events) {
        List<Finding> findings = new ArrayList<>();

        bruteForce(events, findings);
        passwordSpraying(events, findings);
        compromisedLogin(events, findings);
        pathAttack(events, findings, "SQL_INJECTION", "SQL injection attempts", Severity.HIGH,
                "T1190 Exploit Public-Facing Application", SQLI,
                "Requests carried SQL syntax in the URL. Confirm the application uses parameterised "
                        + "queries and check these requests for 200 responses.",
                "Use parameterised queries, validate input server side, and put a WAF rule in front "
                        + "of the affected endpoints.");
        pathAttack(events, findings, "XSS", "Cross-site scripting attempts", Severity.MEDIUM,
                "T1190 Exploit Public-Facing Application", XSS,
                "Requests carried script or event-handler payloads in the URL.",
                "Encode output by context, set a Content-Security-Policy, and sanitise stored input.");
        pathAttack(events, findings, "PATH_TRAVERSAL", "Path traversal attempts", Severity.HIGH,
                "T1190 Exploit Public-Facing Application", TRAVERSAL,
                "Requests tried to climb out of the web root or read system files.",
                "Normalise and validate file paths, never build paths from user input, and run the "
                        + "service with minimal file system permissions.");
        sensitivePaths(events, findings);
        scannerAgents(events, findings);
        forcedBrowsing(events, findings);
        serverErrors(events, findings);
        trafficConcentration(events, findings);
        requestBurst(events, findings);

        findings.sort(Comparator
                .comparing((Finding f) -> f.severity().ordinal())
                .thenComparing(Comparator.comparingInt(Finding::count).reversed()));
        return findings;
    }

    // ------------------------------------------------------------ risk scoring

    /** Sum of the severity weights, capped at 100. */
    public static int riskScore(List<Finding> findings) {
        int total = 0;
        for (Finding finding : findings) {
            total += finding.severity().weight();
        }
        return Math.min(100, total);
    }

    /**
     * CLEAN when nothing was found. Otherwise the higher of the score band and the most serious
     * single finding, so one critical issue is never hidden behind a low total.
     */
    public static String riskLevel(List<Finding> findings) {
        if (findings.isEmpty()) {
            return "CLEAN";
        }
        int score = riskScore(findings);
        Severity bySeverity = findings.stream()
                .map(Finding::severity)
                .min(Comparator.comparingInt(Severity::ordinal))
                .orElse(Severity.LOW);
        Severity byScore = score >= 70 ? Severity.CRITICAL
                : score >= 40 ? Severity.HIGH
                : score >= 15 ? Severity.MEDIUM
                : Severity.LOW;
        return (bySeverity.ordinal() < byScore.ordinal() ? bySeverity : byScore).name();
    }

    // ------------------------------------------------------------------- rules

    private void bruteForce(List<LogEvent> events, List<Finding> out) {
        Map<String, Integer> failures = new LinkedHashMap<>();
        Map<String, Instant[]> span = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.authFailure() && e.ip() != null) {
                failures.merge(e.ip(), 1, Integer::sum);
                widen(span, e.ip(), e.timestamp());
            }
        }

        List<String> evidence = new ArrayList<>();
        int total = 0;
        int worst = 0;
        for (Map.Entry<String, Integer> entry : failures.entrySet()) {
            int count = entry.getValue();
            if (count < BRUTE_FORCE_MIN) {
                continue;
            }
            total += count;
            worst = Math.max(worst, count);
            evidence.add(entry.getKey() + ": " + count + " failed authentications"
                    + duration(span.get(entry.getKey())));
        }
        if (total == 0) {
            return;
        }

        Severity severity = worst >= 50 ? Severity.CRITICAL : worst >= 10 ? Severity.HIGH : Severity.MEDIUM;
        out.add(new Finding("BRUTE_FORCE", "Brute-force login attempts", severity,
                "T1110 Brute Force", total,
                "One or more addresses failed authentication repeatedly, which is the pattern of "
                        + "automated password guessing.",
                top(evidence),
                "Block or rate-limit the sources, enforce key-based SSH or MFA, and install a ban tool "
                        + "such as fail2ban."));
    }

    private void passwordSpraying(List<LogEvent> events, List<Finding> out) {
        Map<String, Set<String>> usersByIp = new LinkedHashMap<>();
        Map<String, Integer> attempts = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.authFailure() && e.ip() != null && e.user() != null) {
                usersByIp.computeIfAbsent(e.ip(), k -> new LinkedHashSet<>()).add(e.user());
                attempts.merge(e.ip(), 1, Integer::sum);
            }
        }

        List<String> evidence = new ArrayList<>();
        int total = 0;
        for (Map.Entry<String, Set<String>> entry : usersByIp.entrySet()) {
            if (entry.getValue().size() < SPRAYING_MIN_USERS) {
                continue;
            }
            total += attempts.get(entry.getKey());
            evidence.add(entry.getKey() + " tried " + entry.getValue().size() + " different accounts ("
                    + String.join(", ", entry.getValue().stream().limit(5).toList()) + ")");
        }
        if (total == 0) {
            return;
        }

        out.add(new Finding("PASSWORD_SPRAYING", "Account enumeration or password spraying",
                Severity.HIGH, "T1110.003 Password Spraying", total,
                "A single address attempted many different account names, which points to guessing "
                        + "which accounts exist rather than attacking one.",
                top(evidence),
                "Disable password logins for SSH, remove unused accounts, and alert on one source "
                        + "touching many usernames."));
    }

    /** A successful login from an address that had already failed several times. */
    private void compromisedLogin(List<LogEvent> events, List<Finding> out) {
        Map<String, Integer> failures = new HashMap<>();
        List<String> evidence = new ArrayList<>();
        int count = 0;

        for (LogEvent e : events) {
            if (e.ip() == null) {
                continue;
            }
            if (e.authFailure()) {
                failures.merge(e.ip(), 1, Integer::sum);
            } else if (isSuccess(e) && failures.getOrDefault(e.ip(), 0) >= BRUTE_FORCE_MIN) {
                count++;
                evidence.add(e.ip() + " logged in as " + (e.user() == null ? "an unknown account" : e.user())
                        + " after " + failures.get(e.ip()) + " failed attempts");
            }
        }
        if (count == 0) {
            return;
        }

        out.add(new Finding("COMPROMISED_LOGIN", "Successful login after repeated failures",
                Severity.CRITICAL, "T1078 Valid Accounts", count,
                "An address that failed to authenticate several times then succeeded. This is the "
                        + "strongest sign that a guessed credential worked.",
                top(evidence),
                "Treat the account as compromised: reset its credentials, revoke sessions and keys, "
                        + "and review what that account did after the login."));
    }

    private void pathAttack(List<LogEvent> events, List<Finding> out, String rule, String title,
                            Severity severity, String mitre, List<String> indicators,
                            String description, String recommendation) {
        Map<String, Integer> byIp = new LinkedHashMap<>();
        List<String> evidence = new ArrayList<>();
        int count = 0;

        for (LogEvent e : events) {
            if (e.path() == null || !containsAny(decode(e.path()), indicators)) {
                continue;
            }
            count++;
            if (e.ip() != null) {
                byIp.merge(e.ip(), 1, Integer::sum);
            }
            evidence.add(describe(e));
        }
        if (count == 0) {
            return;
        }

        out.add(new Finding(rule, title, severity, mitre, count,
                description + " Sources: " + byIp.size() + ".",
                top(evidence), recommendation));
    }

    private void sensitivePaths(List<LogEvent> events, List<Finding> out) {
        Map<String, Integer> byIp = new LinkedHashMap<>();
        List<String> evidence = new ArrayList<>();
        int count = 0;

        for (LogEvent e : events) {
            if (e.path() != null && containsAny(decode(e.path()), SENSITIVE_PATHS)) {
                count++;
                if (e.ip() != null) {
                    byIp.merge(e.ip(), 1, Integer::sum);
                }
                evidence.add(describe(e));
            }
        }
        if (count == 0) {
            return;
        }

        int worst = byIp.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        out.add(new Finding("SENSITIVE_PATH_PROBING", "Probing for sensitive files and admin pages",
                worst >= 10 ? Severity.HIGH : Severity.MEDIUM, "T1595.003 Wordlist Scanning", count,
                "Requests targeted well-known sensitive locations such as environment files, version "
                        + "control folders and admin panels. Sources: " + byIp.size() + ".",
                top(evidence),
                "Make sure these paths are not served, move admin interfaces behind a VPN or allow-list, "
                        + "and rotate any secret that was ever exposed."));
    }

    private void scannerAgents(List<LogEvent> events, List<Finding> out) {
        Map<String, Integer> seen = new LinkedHashMap<>();
        int count = 0;

        for (LogEvent e : events) {
            if (e.userAgent() == null) {
                continue;
            }
            String agent = e.userAgent().toLowerCase(Locale.ROOT);
            for (String scanner : SCANNER_AGENTS) {
                if (agent.contains(scanner)) {
                    count++;
                    seen.merge((e.ip() == null ? "unknown" : e.ip()) + " used " + scanner, 1, Integer::sum);
                    break;
                }
            }
        }
        if (count == 0) {
            return;
        }

        List<String> evidence = new ArrayList<>();
        seen.forEach((who, n) -> evidence.add(who + " (" + n + " requests)"));
        out.add(new Finding("SCANNER_USER_AGENT", "Known security scanner detected", Severity.MEDIUM,
                "T1595.002 Vulnerability Scanning", count,
                "Requests identified themselves as a known scanning or exploitation tool.",
                top(evidence),
                "Block these user agents at the edge and check whether the scan found anything "
                        + "that returned a success status."));
    }

    private void forcedBrowsing(List<LogEvent> events, List<Finding> out) {
        Map<String, Set<String>> missing = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.ip() != null && e.path() != null && e.status() != null && e.status() == 404) {
                missing.computeIfAbsent(e.ip(), k -> new HashSet<>()).add(e.path());
            }
        }

        List<String> evidence = new ArrayList<>();
        int total = 0;
        for (Map.Entry<String, Set<String>> entry : missing.entrySet()) {
            if (entry.getValue().size() >= FORCED_BROWSING_MIN) {
                total += entry.getValue().size();
                evidence.add(entry.getKey() + " requested " + entry.getValue().size() + " different missing pages");
            }
        }
        if (total == 0) {
            return;
        }

        out.add(new Finding("FORCED_BROWSING", "Directory or file enumeration", Severity.MEDIUM,
                "T1595.003 Wordlist Scanning", total,
                "One address requested many different pages that do not exist, which is how content "
                        + "discovery tools work.",
                top(evidence),
                "Rate-limit repeated 404 responses per address and review whether any guessed path "
                        + "returned a real page."));
    }

    private void serverErrors(List<LogEvent> events, List<Finding> out) {
        List<String> evidence = new ArrayList<>();
        int count = 0;
        for (LogEvent e : events) {
            if (e.status() != null && e.status() >= 500) {
                count++;
                evidence.add(describe(e));
            }
        }
        if (count < SERVER_ERRORS_MIN) {
            return;
        }

        out.add(new Finding("SERVER_ERRORS", "Cluster of server errors", count >= 20 ? Severity.HIGH : Severity.MEDIUM,
                null, count,
                "Several requests ended in a 5xx response. Attacks often cause errors before they succeed.",
                top(evidence),
                "Check the application logs for the same timestamps and look for requests that "
                        + "triggered unhandled exceptions."));
    }

    private void trafficConcentration(List<LogEvent> events, List<Finding> out) {
        Map<String, Integer> byIp = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.ip() != null) {
                byIp.merge(e.ip(), 1, Integer::sum);
            }
        }

        int threshold = Math.max(10, events.size() / 3);
        List<String> evidence = new ArrayList<>();
        int total = 0;
        for (Map.Entry<String, Integer> entry : byIp.entrySet()) {
            if (entry.getValue() > threshold) {
                total += entry.getValue();
                evidence.add(entry.getKey() + ": " + entry.getValue() + " requests");
            }
        }
        if (total == 0) {
            return;
        }

        out.add(new Finding("TRAFFIC_CONCENTRATION", "Traffic concentrated on one address", Severity.LOW,
                null, total,
                "A single address produced a large share of all requests.",
                top(evidence),
                "Confirm whether this is a known client or monitor. If not, rate-limit or block it."));
    }

    /** Requests per minute far above the usual rate. Needs timestamps. */
    private void requestBurst(List<LogEvent> events, List<Finding> out) {
        Map<Long, Integer> perMinute = new TreeMap<>();
        int timed = 0;
        for (LogEvent e : events) {
            if (e.timestamp() != null) {
                perMinute.merge(e.timestamp().getEpochSecond() / 60, 1, Integer::sum);
                timed++;
            }
        }
        if (timed < BURST_MIN_EVENTS) {
            return;
        }

        List<Integer> counts = new ArrayList<>(perMinute.values());
        counts.sort(Integer::compare);
        int median = counts.get(counts.size() / 2);
        long peakMinute = -1;
        int peak = 0;
        for (Map.Entry<Long, Integer> entry : perMinute.entrySet()) {
            if (entry.getValue() > peak) {
                peak = entry.getValue();
                peakMinute = entry.getKey();
            }
        }

        if (peak < Math.max(BURST_MIN_PEAK, BURST_MEDIAN_FACTOR * median)) {
            return;
        }

        out.add(new Finding("REQUEST_BURST", "Sudden spike in request rate",
                peak >= 100 ? Severity.HIGH : Severity.MEDIUM, "T1498 Network Denial of Service", peak,
                "The busiest minute had far more requests than the typical minute, which can indicate "
                        + "a flood or an automated tool.",
                List.of("Peak of " + peak + " requests in the minute starting "
                        + Instant.ofEpochSecond(peakMinute * 60) + " (typical minute: " + median + ")"),
                "Add rate limiting at the edge, check whether the spike came from few addresses, and "
                        + "confirm the service stayed healthy."));
    }

    // ----------------------------------------------------------------- helpers

    private static boolean isSuccess(LogEvent e) {
        String raw = e.raw() == null ? "" : e.raw().toLowerCase(Locale.ROOT);
        return SUCCESS_MARKERS.stream().anyMatch(raw::contains);
    }

    private static boolean containsAny(String text, List<String> needles) {
        for (String needle : needles) {
            if (text.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    /** URL-decodes once and lower-cases, so %27 and %3Cscript are seen as what they are. */
    private static String decode(String path) {
        String decoded;
        try {
            decoded = URLDecoder.decode(path, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            decoded = path;
        }
        return decoded.toLowerCase(Locale.ROOT);
    }

    private static String describe(LogEvent e) {
        StringBuilder text = new StringBuilder();
        if (e.method() != null) {
            text.append(e.method()).append(' ');
        }
        text.append(e.path());
        if (e.status() != null) {
            text.append(" -> ").append(e.status());
        }
        if (e.ip() != null) {
            text.append(" from ").append(e.ip());
        }
        return clip(text.toString());
    }

    /** Keeps evidence short and printable, since it comes straight from untrusted log text. */
    private static String clip(String value) {
        StringBuilder clean = new StringBuilder();
        for (int i = 0; i < value.length() && clean.length() < EVIDENCE_WIDTH; i++) {
            char c = value.charAt(i);
            clean.append(c < 32 || c == 127 ? '?' : c);
        }
        return value.length() > EVIDENCE_WIDTH ? clean + "..." : clean.toString();
    }

    private static List<String> top(List<String> evidence) {
        return evidence.stream().distinct().limit(EVIDENCE_LIMIT).toList();
    }

    private static void widen(Map<String, Instant[]> span, String ip, Instant when) {
        if (when == null) {
            return;
        }
        Instant[] range = span.computeIfAbsent(ip, k -> new Instant[]{when, when});
        if (when.isBefore(range[0])) {
            range[0] = when;
        }
        if (when.isAfter(range[1])) {
            range[1] = when;
        }
    }

    private static String duration(Instant[] range) {
        if (range == null) {
            return "";
        }
        long seconds = range[1].getEpochSecond() - range[0].getEpochSecond();
        return seconds <= 0 ? "" : " over " + seconds + "s";
    }
}
