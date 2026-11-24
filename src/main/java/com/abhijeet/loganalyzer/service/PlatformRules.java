package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import com.abhijeet.loganalyzer.model.Severity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Predicate;

/**
 * Detection rules for the non-web formats: Windows Security events, AWS CloudTrail, firewall
 * logs, Java application logs and Docker / Kubernetes logs. Like {@link FindingDetector}, every
 * rule is deterministic and works on parsed events only.
 */
final class PlatformRules {

    static final int PORT_SCAN_MIN_PORTS = 10;
    static final int FIREWALL_BLOCKS_MIN = 20;
    static final int EXCEPTIONS_MIN = 3;
    static final int ERROR_BURST_MIN = 10;
    static final int PROBE_FAILURES_MIN = 3;

    /** IAM calls that grant or extend access, not just tidy it up. */
    private static final List<String> PRIVILEGE_GRANTING = List.of(
            "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy",
            "PutGroupPolicy", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
            "UpdateAssumeRolePolicy", "AddUserToGroup", "CreateUser");

    private PlatformRules() {
    }

    static final int WEB_LOGIN_MIN = 10;
    static final int SUDO_FAILURES_MIN = 3;

    private static final java.util.regex.Pattern LOGIN_PATH = java.util.regex.Pattern.compile(
            "(?i)(login|signin|sign-in|logon|wp-login\\.php|xmlrpc\\.php|/auth\\b|/session|/oauth/token|"
                    + "j_security_check|/api/token)");

    /** sudo commands that hand out a shell or change who may do what. */
    private static final List<String> RISKY_COMMANDS = List.of(
            "/bin/bash", "/bin/sh", "/bin/zsh", "bash -i", "sh -i", "/usr/bin/su", " su ", "passwd", "visudo",
            "/etc/sudoers", "/etc/shadow", "useradd", "usermod", "chmod +s", "chmod u+s", "nc -e", "crontab");

    /** CloudTrail deletions that destroy data or production capacity. */
    private static final List<String> HIGH_IMPACT_DELETES = List.of(
            "DeleteBucket", "DeleteDBInstance", "DeleteDBCluster", "TerminateInstances", "DeleteSnapshot",
            "DeleteDBSnapshot", "DeleteDBClusterSnapshot", "DeleteVolume", "DeleteBackupVault",
            "DeleteRecoveryPoint", "DeleteTable", "ScheduleKeyDeletion", "DeleteFileSystem");

    static void detect(List<LogEvent> events, List<Finding> out) {
        web(events, out);
        ssh(events, out);
        linux(events, out);
        windows(events, out);
        cloudTrail(events, out);
        firewall(events, out);
        application(events, out);
        containers(events, out);
    }

    // -------------------------------------------------------------------- Web

    private static void web(List<LogEvent> events, List<Finding> out) {
        Map<String, Integer> attempts = new LinkedHashMap<>();
        Map<String, Set<String>> paths = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.ip() == null || e.path() == null || e.status() == null) {
                continue;
            }
            boolean post = e.method() == null || "POST".equalsIgnoreCase(e.method());
            boolean loginReply = e.status() == 200 || e.status() == 401 || e.status() == 403 || e.status() == 302;
            if (post && loginReply && LOGIN_PATH.matcher(e.path()).find()) {
                attempts.merge(e.ip(), 1, Integer::sum);
                paths.computeIfAbsent(e.ip(), k -> new LinkedHashSet<>()).add(e.path().split("\\?")[0]);
            }
        }
        List<String> evidence = new ArrayList<>();
        int total = 0;
        for (Map.Entry<String, Integer> entry : attempts.entrySet()) {
            if (entry.getValue() >= WEB_LOGIN_MIN) {
                total += entry.getValue();
                evidence.add(entry.getKey() + ": " + entry.getValue() + " login requests to "
                        + String.join(", ", paths.get(entry.getKey())));
            }
        }
        if (total > 0) {
            out.add(new Finding("WEB_LOGIN_BRUTE_FORCE", "Brute force against a web login",
                    Severity.HIGH, MitreMapping.technique("WEB_LOGIN_BRUTE_FORCE"), total,
                    "Addresses sent many login requests to web sign-in endpoints, the pattern of password "
                            + "guessing or credential stuffing.",
                    FindingDetector.top(evidence),
                    "Rate-limit and add CAPTCHA or lockout on the login endpoint, enable MFA, and block "
                            + "the sources; disable xmlrpc.php if WordPress does not need it."));
        }
    }

    // -------------------------------------------------------------------- SSH

    private static void ssh(List<LogEvent> events, List<Finding> out) {
        List<LogEvent> root = events.stream()
                .filter(e -> e.format() == LogFormat.SSH && "root".equals(e.user()))
                .toList();
        if (root.isEmpty()) {
            return;
        }
        long failures = root.stream().filter(LogEvent::authFailure).count();
        boolean success = root.stream().anyMatch(e -> !e.authFailure()
                && e.raw() != null && e.raw().toLowerCase(java.util.Locale.ROOT).contains("accepted"));
        if (failures == 0 && !success) {
            return;
        }
        Map<String, Integer> byIp = new LinkedHashMap<>();
        root.forEach(e -> byIp.merge(e.ip() == null ? "unknown" : e.ip(), 1, Integer::sum));
        List<String> evidence = new ArrayList<>();
        if (success) {
            root.stream().filter(e -> !e.authFailure()).forEach(e ->
                    evidence.add("root logged in over SSH" + from(e) + at(e)));
        }
        byIp.forEach((ip, n) -> evidence.add(ip + ": " + n + " root login attempts"));
        out.add(new Finding("SSH_ROOT_LOGIN", success ? "Root logged in over SSH" : "SSH login attempts as root",
                success || failures >= 10 ? Severity.HIGH : Severity.MEDIUM, MitreMapping.technique("SSH_ROOT_LOGIN"),
                root.size(),
                "Logins were attempted directly as root" + (success ? ", and at least one succeeded" : "")
                        + ". Root is the first account attackers guess.",
                FindingDetector.top(evidence),
                "Set PermitRootLogin no in sshd_config, log in as a named user and use sudo, and keep "
                        + "password authentication off."));
    }

    // ------------------------------------------------------------------ Linux

    private static void linux(List<LogEvent> events, List<Finding> out) {
        List<LogEvent> elevation = events.stream()
                .filter(e -> e.is("sudo_command") || e.is("su_session"))
                .toList();
        if (!elevation.isEmpty()) {
            List<LogEvent> risky = elevation.stream().filter(PlatformRules::risky).toList();
            List<LogEvent> shown = new ArrayList<>(risky);
            elevation.stream().filter(e -> !risky.contains(e)).forEach(shown::add);
            out.add(new Finding("SUDO_SU_USAGE", "Privilege elevation with sudo or su",
                    risky.isEmpty() ? Severity.LOW : Severity.MEDIUM, MitreMapping.technique("SUDO_SU_USAGE"),
                    elevation.size(),
                    elevation.size() + " sudo or su sessions" + (risky.isEmpty() ? "."
                            : ", " + risky.size() + " of them opening a shell or touching accounts and sudo rules."),
                    evidence(shown, e -> e.is("sudo_command")
                            ? name(e.user()) + " ran " + e.detail() + at(e)
                            : name(e.user()) + " switched to " + name(e.detail()) + at(e)),
                    "Check each elevation against an approved change, give users specific sudo commands "
                            + "instead of a full shell, and send auth.log to a central collector."));
        }

        List<LogEvent> failures = events.stream().filter(e -> e.is("sudo_failure") || e.is("su_failure")).toList();
        if (failures.size() >= SUDO_FAILURES_MIN) {
            out.add(new Finding("SUDO_SU_FAILURES", "Failed sudo or su attempts", Severity.MEDIUM,
                    MitreMapping.technique("SUDO_SU_FAILURES"), failures.size(),
                    "Users repeatedly failed to authenticate to sudo or su, which can mean someone with a "
                            + "foothold is guessing the password to become root.",
                    evidence(failures, e -> name(e.user()) + (e.is("su_failure") ? " failed su" : " failed sudo") + at(e)),
                    "Confirm with the user, lock the account if it was not them, and check what else that "
                            + "account did."));
        }
    }

    private static boolean risky(LogEvent e) {
        if (e.is("su_session")) {
            return "root".equals(e.detail());
        }
        String command = " " + (e.detail() == null ? "" : e.detail()) + " ";
        return RISKY_COMMANDS.stream().anyMatch(command::contains);
    }

    // ---------------------------------------------------------------- Windows

    private static void windows(List<LogEvent> events, List<Finding> out) {
        simple(events, out, e -> e.is("audit_log_cleared"), "AUDIT_LOG_CLEARED",
                "Security audit log cleared", Severity.CRITICAL, MitreMapping.technique("AUDIT_LOG_CLEARED"),
                "Event 1102: someone cleared the Security event log. Attackers do this to remove traces of "
                        + "what they did.",
                e -> "Log cleared" + by(e) + at(e),
                "Find out who cleared the log and why, collect logs from other sources (SIEM, backups) for "
                        + "the same period, and forward event logs off the host so they cannot be erased.");

        simple(events, out, e -> e.is("added_to_group"), "PRIVILEGED_GROUP_CHANGE",
                "Account added to a privileged group", Severity.HIGH, MitreMapping.technique("PRIVILEGED_GROUP_CHANGE"),
                "An account was added to a security or admin group (Windows events 4728/4732/4756, or the "
                        + "Linux sudo, wheel, adm or docker groups), which can grant administrator rights.",
                e -> e.format() == LogFormat.WINDOWS_EVENT
                        ? "Event " + e.detail() + ": " + name(e.user()) + " added to a group" + at(e)
                        : name(e.user()) + " added to group " + name(e.detail()) + at(e),
                "Confirm each membership change was approved, remove any that were not, and alert on "
                        + "changes to Administrators and Domain Admins.");

        simple(events, out, e -> e.is("account_created"), "ACCOUNT_CREATED",
                "New user account created", Severity.MEDIUM, MitreMapping.technique("ACCOUNT_CREATED"),
                "A new account was created (Windows event 4720 or Linux useradd). Attackers create accounts "
                        + "to keep access.",
                e -> "Account " + name(e.user()) + " created" + at(e),
                "Check that each new account matches a request, disable unknown ones, and review what "
                        + "they have logged in to since.");

        List<LogEvent> privileged = events.stream()
                .filter(e -> e.is("special_privileges") || e.is("privileged_service") || e.is("privileged_object"))
                .toList();
        if (!privileged.isEmpty()) {
            Map<String, Integer> byUser = new LinkedHashMap<>();
            privileged.forEach(e -> byUser.merge(name(e.user()), 1, Integer::sum));
            List<String> evidence = new ArrayList<>();
            byUser.forEach((u, n) -> evidence.add(u + ": " + n + " privileged logons or privilege uses"));
            out.add(new Finding("PRIVILEGE_USE", "Administrator privileges used", Severity.LOW,
                    MitreMapping.technique("PRIVILEGE_USE"), privileged.size(),
                    "Events 4672/4673/4674: accounts logged on with or used sensitive privileges. Normal for "
                            + "admins; worth checking for accounts that should not have them.",
                    FindingDetector.top(evidence),
                    "Confirm every account here is meant to be an administrator, and remove admin rights "
                            + "that are not needed day to day."));
        }

        simple(events, out, e -> e.is("account_lockout"), "ACCOUNT_LOCKOUT",
                "Accounts locked out", Severity.MEDIUM, MitreMapping.technique("ACCOUNT_LOCKOUT"),
                "Event 4740: accounts were locked after too many failed passwords, usually a sign of "
                        + "password guessing.",
                e -> "Account " + name(e.user()) + " locked out" + at(e),
                "Find the source of the failed logons (event 4625), block it, and check whether the "
                        + "account's password needs resetting.");
    }

    // -------------------------------------------------------------- CloudTrail

    private static void cloudTrail(List<LogEvent> events, List<Finding> out) {
        simple(events, out, e -> e.is("logging_disabled"), "CLOUD_LOGGING_DISABLED",
                "Cloud audit logging stopped or deleted", Severity.CRITICAL,
                MitreMapping.technique("CLOUD_LOGGING_DISABLED"),
                "A CloudTrail trail, GuardDuty detector, VPC flow log or Security Hub was stopped or deleted. "
                        + "Attackers turn off logging before acting.",
                e -> e.detail() + by(e) + from(e) + at(e),
                "Turn logging back on immediately, protect trails with an SCP that denies StopLogging and "
                        + "DeleteTrail, and investigate the identity that made the call.");

        List<LogEvent> root = events.stream()
                .filter(e -> e.format() == LogFormat.CLOUDTRAIL && "root".equals(e.user()))
                .toList();
        if (!root.isEmpty()) {
            boolean console = root.stream().anyMatch(e -> e.category() != null && e.category().startsWith("console_login")
                    && !e.authFailure());
            out.add(new Finding("ROOT_ACCOUNT_USAGE", "AWS root account used",
                    console ? Severity.CRITICAL : Severity.HIGH, MitreMapping.technique("ROOT_ACCOUNT_USAGE"),
                    root.size(),
                    "The AWS root user made API calls" + (console ? " and signed in to the console" : "")
                            + ". Root has unrestricted access and should almost never be used.",
                    evidence(root, e -> e.detail() + from(e) + at(e)),
                    "Confirm the activity was planned, make sure root has hardware MFA and no access keys, "
                            + "and use IAM roles for day-to-day work."));
        }

        simple(events, out, e -> e.is("console_login_no_mfa"), "CONSOLE_LOGIN_WITHOUT_MFA",
                "Console sign-in without MFA", Severity.HIGH, MitreMapping.technique("CONSOLE_LOGIN_WITHOUT_MFA"),
                "Users signed in to the AWS console with a password only. A stolen password is enough "
                        + "to take over these accounts.",
                e -> name(e.user()) + " signed in without MFA" + from(e) + at(e),
                "Require MFA for every console user, for example with an IAM policy that denies actions "
                        + "when aws:MultiFactorAuthPresent is false.");

        List<LogEvent> deleted = events.stream().filter(e -> e.is("resource_deleted")).toList();
        if (!deleted.isEmpty()) {
            boolean impact = deleted.stream().anyMatch(e -> HIGH_IMPACT_DELETES.contains(e.detail()));
            out.add(new Finding("DELETED_RESOURCES", "Cloud resources deleted",
                    impact || deleted.size() >= 10 ? Severity.HIGH : Severity.MEDIUM,
                    MitreMapping.technique("DELETED_RESOURCES"), deleted.size(),
                    deleted.size() + " AWS resources were deleted or terminated"
                            + (impact ? ", including storage, databases, instances or backups" : "") + ".",
                    evidence(deleted, e -> e.detail() + by(e) + from(e) + at(e)),
                    "Confirm each deletion was planned, restore from backups or versioning where it was not, "
                            + "and protect critical resources with deletion protection and SCPs."));
        }

        List<LogEvent> iam = events.stream().filter(e -> e.is("iam_change")).toList();
        if (!iam.isEmpty()) {
            boolean granting = iam.stream().anyMatch(e -> PRIVILEGE_GRANTING.contains(e.detail()));
            out.add(new Finding("IAM_CHANGES", "IAM permissions changed",
                    granting || iam.size() >= 10 ? Severity.HIGH : Severity.MEDIUM, MitreMapping.technique("IAM_CHANGES"),
                    iam.size(),
                    "IAM users, roles, policies or keys were created or changed"
                            + (granting ? ", including calls that grant new access" : "") + ".",
                    evidence(iam, e -> e.detail() + by(e) + from(e) + at(e)),
                    "Review each change against a ticket, remove unexpected policies and access keys, and "
                            + "alert on IAM changes outside your deployment pipeline."));
        }
    }

    // --------------------------------------------------------------- Firewall

    private static void firewall(List<LogEvent> events, List<Finding> out) {
        Map<String, Set<Integer>> ports = new LinkedHashMap<>();
        Map<String, Integer> blocks = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.format() != LogFormat.FIREWALL || e.ip() == null) {
                continue;
            }
            if (e.port() != null) {
                ports.computeIfAbsent(e.ip(), k -> new LinkedHashSet<>()).add(e.port());
            }
            if (e.is("firewall_block")) {
                blocks.merge(e.ip(), 1, Integer::sum);
            }
        }

        List<String> scanEvidence = new ArrayList<>();
        int scanned = 0;
        for (Map.Entry<String, Set<Integer>> entry : ports.entrySet()) {
            if (entry.getValue().size() >= PORT_SCAN_MIN_PORTS) {
                scanned += entry.getValue().size();
                scanEvidence.add(entry.getKey() + " probed " + entry.getValue().size() + " ports ("
                        + String.join(", ", entry.getValue().stream().limit(8).map(String::valueOf).toList())
                        + (entry.getValue().size() > 8 ? ", ..." : "") + ")");
            }
        }
        if (scanned > 0) {
            out.add(new Finding("PORT_SCAN", "Port scan", Severity.HIGH, MitreMapping.technique("PORT_SCAN"),
                    scanned,
                    "One address tried many different destination ports, which is how attackers map "
                            + "which services are exposed.",
                    FindingDetector.top(scanEvidence),
                    "Keep the source blocked, close every port that does not need to be public, and check "
                            + "whether any probed port answered."));
        }

        int total = blocks.values().stream().mapToInt(Integer::intValue).sum();
        if (total >= FIREWALL_BLOCKS_MIN) {
            int worst = blocks.values().stream().mapToInt(Integer::intValue).max().orElse(0);
            List<String> evidence = new ArrayList<>();
            blocks.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .forEach(entry -> evidence.add(entry.getKey() + ": " + entry.getValue() + " blocked connections"));
            out.add(new Finding("FIREWALL_BLOCKS", "Many connections blocked by the firewall",
                    worst >= 50 ? Severity.MEDIUM : Severity.LOW, null, total,
                    "The firewall blocked " + total + " connections from " + blocks.size() + " addresses.",
                    FindingDetector.top(evidence),
                    "The firewall is doing its job; consider banning persistent sources upstream and "
                            + "check that nothing allowed came from the same addresses."));
        }
    }

    // ------------------------------------------------------------ Application

    private static void application(List<LogEvent> events, List<Finding> out) {
        Map<String, Integer> byClass = new LinkedHashMap<>();
        Map<String, Integer> causes = new LinkedHashMap<>();
        int exceptions = 0;
        for (LogEvent e : events) {
            if (e.is("exception") && e.detail() != null) {
                exceptions++;
                byClass.merge(e.detail(), 1, Integer::sum);
            } else if (e.is("caused_by") && e.detail() != null) {
                causes.merge(e.detail(), 1, Integer::sum);
            }
        }
        if (exceptions >= EXCEPTIONS_MIN) {
            List<String> evidence = new ArrayList<>();
            byClass.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .forEach(entry -> evidence.add(entry.getKey() + " x" + entry.getValue()));
            causes.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .limit(2)
                    .forEach(entry -> evidence.add("root cause: " + entry.getKey() + " x" + entry.getValue()));
            out.add(new Finding("APP_EXCEPTIONS", "Application exceptions",
                    exceptions >= 20 ? Severity.HIGH : Severity.MEDIUM, null, exceptions,
                    "The application threw " + exceptions + " exceptions of " + byClass.size()
                            + " types. Repeated exceptions usually mean a bug or a failing dependency.",
                    FindingDetector.top(evidence),
                    "Fix the most frequent exception first, starting from its root cause, and add an alert "
                            + "on the exception rate."));
        }

        Map<Long, Integer> perMinute = new TreeMap<>();
        for (LogEvent e : events) {
            boolean error = "ERROR".equals(e.level()) || "FATAL".equals(e.level());
            boolean logLine = !e.is("stack_frame") && !e.is("caused_by");
            if (error && logLine && e.timestamp() != null) {
                perMinute.merge(e.timestamp().getEpochSecond() / 60, 1, Integer::sum);
            }
        }
        if (!perMinute.isEmpty()) {
            List<Integer> counts = new ArrayList<>(perMinute.values());
            counts.sort(Integer::compare);
            // Lower median, so with only a few busy minutes the burst itself is not the baseline.
            int median = counts.get((counts.size() - 1) / 2);
            Map.Entry<Long, Integer> peak = perMinute.entrySet().stream()
                    .max(Map.Entry.comparingByValue()).orElseThrow();
            boolean spike = perMinute.size() == 1 || peak.getValue() >= 3 * median;
            if (peak.getValue() >= ERROR_BURST_MIN && spike) {
                out.add(new Finding("ERROR_BURST", "Burst of application errors",
                        peak.getValue() >= 50 ? Severity.HIGH : Severity.MEDIUM, null, peak.getValue(),
                        "The application logged " + peak.getValue() + " ERROR lines in a single minute.",
                        List.of("Peak of " + peak.getValue() + " errors in the minute starting "
                                + java.time.Instant.ofEpochSecond(peak.getKey() * 60)
                                + " (typical minute with errors: " + median + ")"),
                        "Check what changed at that time (deploy, dependency outage, traffic spike) and "
                                + "look at the first error of the burst, not the last."));
            }
        }
    }

    // ------------------------------------------------------------- Containers

    private static void containers(List<LogEvent> events, List<Finding> out) {
        List<LogEvent> crashes = events.stream().filter(e -> e.is("crash_loop")).toList();
        if (!crashes.isEmpty()) {
            Set<String> workloads = workloads(crashes);
            out.add(new Finding("CRASH_LOOP", "Containers in a crash loop",
                    workloads.size() >= 3 || crashes.size() >= 20 ? Severity.CRITICAL : Severity.HIGH, null,
                    crashes.size(),
                    "Containers keep crashing and restarting (CrashLoopBackOff)"
                            + (workloads.isEmpty() ? "." : ": " + String.join(", ", workloads) + "."),
                    evidence(crashes, e -> name(e.detail()) + ": " + FindingDetector.clip(e.raw())),
                    "Read the logs of the previous container run (kubectl logs --previous), fix the start-up "
                            + "error, and check recent config or image changes."));
        }

        List<LogEvent> oom = events.stream().filter(e -> e.is("oom_kill")).toList();
        if (!oom.isEmpty()) {
            Set<String> workloads = workloads(oom);
            out.add(new Finding("OOM_KILL", "Processes killed for running out of memory", Severity.HIGH, null,
                    oom.size(),
                    "The kernel or Kubernetes killed processes that exceeded their memory limit"
                            + (workloads.isEmpty() ? "." : ": " + String.join(", ", workloads) + "."),
                    evidence(oom, e -> name(e.detail()) + ": " + FindingDetector.clip(e.raw())),
                    "Raise the memory limit or fix the leak; for Java, size the heap below the container "
                            + "limit (-XX:MaxRAMPercentage) and check for unbounded caches."));
        }

        List<LogEvent> probes = events.stream().filter(e -> e.is("probe_failed")).toList();
        if (probes.size() >= PROBE_FAILURES_MIN) {
            out.add(new Finding("PROBE_FAILURES", "Health probes failing", Severity.MEDIUM, null, probes.size(),
                    "Liveness, readiness or startup probes failed " + probes.size() + " times, so pods are "
                            + "being restarted or taken out of service.",
                    evidence(probes, e -> name(e.detail()) + ": " + FindingDetector.clip(e.raw())),
                    "Check the probe endpoint and its timeouts; a slow start-up needs a startup probe, "
                            + "not a shorter liveness timeout."));
        }

        simple(events, out, e -> e.is("image_pull_error"), "IMAGE_PULL_ERRORS",
                "Container images failed to pull", Severity.MEDIUM, null,
                "Kubernetes could not pull container images, so those pods cannot start.",
                e -> name(e.detail()) + ": " + FindingDetector.clip(e.raw()),
                "Check the image name and tag, registry credentials (imagePullSecrets) and registry "
                        + "rate limits.");
    }

    // ---------------------------------------------------------------- helpers

    private static void simple(List<LogEvent> events, List<Finding> out, Predicate<LogEvent> match,
                               String rule, String title, Severity severity, String mitre, String description,
                               java.util.function.Function<LogEvent, String> describe, String recommendation) {
        List<LogEvent> hits = events.stream().filter(match).toList();
        if (hits.isEmpty()) {
            return;
        }
        out.add(new Finding(rule, title, severity, mitre, hits.size(), description,
                evidence(hits, describe), recommendation));
    }

    private static List<String> evidence(List<LogEvent> hits, java.util.function.Function<LogEvent, String> describe) {
        List<String> lines = new ArrayList<>();
        for (LogEvent e : hits) {
            lines.add(FindingDetector.clip(describe.apply(e)));
        }
        return FindingDetector.top(lines);
    }

    private static Set<String> workloads(List<LogEvent> hits) {
        Set<String> names = new HashSet<>();
        for (LogEvent e : hits) {
            if (e.detail() != null) {
                names.add(e.detail());
            }
        }
        return new java.util.TreeSet<>(names);
    }

    private static String name(String value) {
        return value == null ? "unknown" : value;
    }

    private static String by(LogEvent e) {
        return e.user() == null ? "" : " by " + e.user();
    }

    private static String from(LogEvent e) {
        return e.ip() == null ? "" : " from " + e.ip();
    }

    private static String at(LogEvent e) {
        return e.timestamp() == null ? "" : " at " + e.timestamp();
    }
}
