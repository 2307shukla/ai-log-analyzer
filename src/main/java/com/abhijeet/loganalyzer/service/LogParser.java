package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses raw log text into structured events, detecting the format of every line.
 *
 * Supported formats (see {@link LogFormat}):
 *   - Apache / Nginx "combined" access logs
 *   - SSH auth logs (sshd, syslog timestamps)
 *   - Linux syslog / auth.log: sudo and su use, new users, group changes
 *   - JSON lines, one object per line (nginx, Caddy, app loggers)
 *   - Spring Boot / Java application logs, including stack traces
 *   - Windows Security Event logs (key=value, Event Viewer CSV text, or JSON / winlogbeat)
 *   - AWS CloudTrail (a {"Records": [...]} document or one event per line)
 *   - UFW / iptables firewall logs
 *   - Docker / Kubernetes logs (Docker json-file, kubelet and kubectl event text)
 *
 * Anything unrecognised still produces a LogEvent carrying the raw line, so
 * no evidence is silently discarded.
 */
@Service
public class LogParser {

    // Uploaded logs are untrusted, so no pattern below may backtrack over the same text two ways
    // (polynomial ReDoS): repeats that border each other are possessive (++, *+) and the trailing
    // ".*" runs with DOTALL, because lines() leaves characters such as U+2028 that "." would stop at.

    /** Apache/Nginx combined log format. */
    private static final Pattern COMBINED = Pattern.compile(
            "^(\\S++) \\S++ \\S++ \\[([^\\]]++)] \"(\\S++) ([^\\s\"]++)[^\"]*+\" (\\d{3}) (\\S++)"
                    + "(?: \"([^\"]*+)\" \"([^\"]*+)\")?+.*$", Pattern.DOTALL);

    /** First IPv4 address anywhere in the line - used as a fallback. */
    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b");

    /** Syslog time without a year, for example "Nov 12 03:20:11". */
    private static final Pattern SYSLOG_TIME = Pattern.compile(
            "^([A-Z][a-z]{2})\\s+(\\d{1,2})\\s+(\\d{2}):(\\d{2}):(\\d{2})\\b");

    /** An ISO-8601 timestamp anywhere in the line. */
    private static final Pattern ISO_TIME = Pattern.compile(
            "\\b(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d{1,9})?(?:Z|[+-]\\d{2}:?\\d{2})?)");

    /** Windows Event Viewer text time, for example "11/12/2026 8:04:11 AM". */
    private static final Pattern US_TIME = Pattern.compile(
            "\\b(\\d{1,2})/(\\d{1,2})/(\\d{4}) (\\d{1,2}):(\\d{2}):(\\d{2}) ?(AM|PM)?");

    /** Year inside an Apache time or an ISO date, used to date syslog lines. */
    private static final Pattern YEAR_HINT = Pattern.compile(
            "\\[\\d{2}/[A-Za-z]{3}/(\\d{4}):|\\b(20\\d{2})-\\d{2}-\\d{2}[T ]");

    /** "Failed password for [invalid user] NAME from" and "Accepted publickey for NAME from". */
    private static final Pattern AUTH_USER = Pattern.compile(
            "(?i)(?:failed|accepted) \\S+ for (?:invalid user )?(\\S+) from ");

    private static final Pattern INVALID_USER = Pattern.compile("(?i)invalid user (\\S+) from ");

    // ------------------------------------------------------------ Spring Boot

    /** Spring Boot default: "2026-11-12T08:00:01.123Z ERROR 1234 --- [app] [main] c.e.Foo : msg". */
    private static final Pattern SPRING = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d{1,9})?(?:Z|[+-]\\d{2}:?\\d{2})?)\\s++"
                    + "(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\\s++(.*)$", Pattern.DOTALL);

    /** Logback / log4j: "2026-11-12 08:00:01,123 [http-nio-8080-exec-1] ERROR c.e.Foo - msg". */
    private static final Pattern LOGBACK = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d{1,9})?(?:Z|[+-]\\d{2}:?\\d{2})?)\\s++"
                    + "\\[[^\\]]*+]\\s++(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\\s++(.*)$", Pattern.DOTALL);

    /** Words made of letters, digits, "_", "$" and dots: the only places an exception name can be. */
    private static final Pattern DOTTED_WORD = Pattern.compile("[\\w$.]++");

    /** Longer dotted words are not class names; skipping them bounds the work per word. */
    private static final int MAX_CLASS_NAME = 300;

    /** 9999-12-31T23:59:59.999Z in epoch milliseconds: the largest numeric timestamp accepted. */
    private static final double MAX_EPOCH_MILLIS = 253_402_300_799_999d;

    private static final Pattern EXCEPTION_HEADER = Pattern.compile(
            "^((?:[a-zA-Z_$][\\w$]*\\.)+[A-Z][\\w$]*(?:Exception|Error|Throwable))(?::.*)?$");

    private static final String CAUSED_BY_PREFIX = "Caused by: ";

    private static final Pattern CAUSED_BY = Pattern.compile(
            "^" + CAUSED_BY_PREFIX + "((?:[a-zA-Z_$][\\w$]*\\.)+[A-Z][\\w$]*)(?::.*)?$");

    private static final Pattern STACK_FRAME = Pattern.compile(
            "^(?:at [\\w$.<>/]+\\(.*\\)|\\.\\.\\. \\d+ (?:more|common frames omitted)|Suppressed: .*)$");

    // ----------------------------------------------------------------- Syslog

    /** "Nov 12 03:20:11 host program[pid]: message", or the same with an ISO time first. */
    private static final Pattern SYSLOG_HEADER = Pattern.compile(
            "^(?:[A-Z][a-z]{2}\\s++\\d{1,2}\\s++\\d{2}:\\d{2}:\\d{2}|\\d{4}-\\d{2}-\\d{2}T\\S++)\\s++\\S++\\s++"
                    + "([\\w.()/-]+?)(?:\\[\\d+])?:\\s*+(.*)$", Pattern.DOTALL);

    private static final String SUDO_SEPARATOR = " : ";
    private static final String SUDO_COMMAND = "COMMAND=";
    private static final Pattern SU_TARGET = Pattern.compile(
            "(?:\\(to (\\S+)\\) (\\S+) on|session opened for user (\\S+?)(?:\\(uid=\\d+\\))? by (\\S+?)(?:\\(uid=\\d+\\))?$"
                    + "|Successful su for (\\S+) by (\\S+))");
    private static final Pattern PAM_USER = Pattern.compile("\\buser=(\\S+)");
    private static final Pattern NEW_USER = Pattern.compile("new user: name=([^,\\s]+)");
    private static final Pattern GROUP_ADD = Pattern.compile("add '([^']+)' to group '([^']+)'");
    private static final List<String> PRIVILEGED_GROUPS = List.of("sudo", "wheel", "admin", "root", "adm", "docker");

    // ---------------------------------------------------------------- Windows

    private static final Pattern WIN_EVENT_ID = Pattern.compile(
            "(?i)(?:\\bEvent[_ ]?ID\\s*[=:]\\s*\"?|Microsoft-Windows-Security-Auditing[,\\t ]+)(\\d{3,5})\\b");

    private static final Pattern WIN_USER = Pattern.compile(
            "(?i)(?:TargetUserName|Account Name)\\s*[=:]\\s*\"?([^\\s\",]+)");

    /** Group-membership events name both the member and the group; the member is the account. */
    private static final Pattern WIN_MEMBER = Pattern.compile("(?i)MemberName\\s*[=:]\\s*\"?([^\\s\",]+)");

    private static final Pattern WIN_SUBJECT = Pattern.compile("(?i)SubjectUserName\\s*[=:]\\s*\"?([^\\s\",]+)");

    private static final Pattern WIN_IP = Pattern.compile(
            "(?i)(?:IpAddress|Source Network Address)\\s*[=:]\\s*\"?([0-9a-fA-F:.]+)");

    private static final Map<String, String> WINDOWS_CATEGORIES = Map.ofEntries(
            Map.entry("4625", "logon_failure"),
            Map.entry("4624", "logon_success"),
            Map.entry("4720", "account_created"),
            Map.entry("4728", "added_to_group"),
            Map.entry("4732", "added_to_group"),
            Map.entry("4756", "added_to_group"),
            Map.entry("4740", "account_lockout"),
            Map.entry("1102", "audit_log_cleared"),
            Map.entry("4672", "special_privileges"),
            Map.entry("4673", "privileged_service"),
            Map.entry("4674", "privileged_object"));

    // --------------------------------------------------------------- Firewall

    private static final Pattern FW_SRC = Pattern.compile("\\bSRC=(\\S+)");
    private static final Pattern FW_DST = Pattern.compile("\\bDST=(\\S+)");
    private static final Pattern FW_DPT = Pattern.compile("\\bDPT=(\\d+)");
    private static final Pattern FW_BLOCK = Pattern.compile("(?i)\\b(?:BLOCK|DROP|DROPPED|REJECT|DENY|DENIED)\\b");

    // -------------------------------------------------------------- Container

    private static final Map<String, String> CONTAINER_MARKERS = Map.ofEntries(
            Map.entry("crashloopbackoff", "crash_loop"),
            Map.entry("back-off restarting failed container", "crash_loop"),
            Map.entry("oomkilled", "oom_kill"),
            Map.entry("out of memory: killed process", "oom_kill"),
            Map.entry("memory cgroup out of memory", "oom_kill"),
            Map.entry("oom-kill", "oom_kill"),
            Map.entry("liveness probe failed", "probe_failed"),
            Map.entry("readiness probe failed", "probe_failed"),
            Map.entry("startup probe failed", "probe_failed"),
            Map.entry("imagepullbackoff", "image_pull_error"),
            Map.entry("errimagepull", "image_pull_error"),
            Map.entry("failed to pull image", "image_pull_error"),
            Map.entry("evicted", "evicted"));

    private static final List<String> CONTAINER_HINTS = List.of(
            "kubelet", "containerd", "dockerd", "pod/", "kube-", "deployment/", "replicaset/");

    private static final Pattern WORKLOAD = Pattern.compile(
            "(?:\\bpod/([\\w.-]+)|\\bpod=\"?(?:[\\w-]+/)?([\\w.-]+)|Killed process \\d+ \\(([^)]+)\\)"
                    + "|\\bcontainer \"?([\\w.-]+)\"?)");

    private static final Pattern COMPACT_OFFSET = Pattern.compile("([+-]\\d{2})(\\d{2})$");

    private static final DateTimeFormatter APACHE_TIME =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    private static final List<String> MONTHS = List.of(
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec");

    private static final String[] AUTH_FAILURE_MARKERS = {
            "failed password", "failed publickey", "invalid user",
            "authentication failure", "failed login", "access denied"
    };

    private static final List<String> IAM_CHANGE_PREFIXES = List.of(
            "Create", "Delete", "Attach", "Detach", "Put", "Update", "Add", "Remove",
            "Change", "Deactivate", "Upload", "Set");

    private static final List<String> DELETE_PREFIXES = List.of(
            "Delete", "Terminate", "Purge", "Destroy", "ScheduleKeyDeletion");

    private static final List<String> LOGGING_DISABLED = List.of(
            "StopLogging", "DeleteTrail", "DeleteDetector", "DeleteFlowLogs", "DisableSecurityHub");

    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ObjectReader strictReader = mapper.readerFor(JsonNode.class)
            .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public LogParser() {
        this(Clock.systemUTC());
    }

    public LogParser(Clock clock) {
        this.clock = clock;
    }

    /** Result of a bounded parse: the events, how many lines the input had, and whether it was cut. */
    public record ParseResult(List<LogEvent> events, int totalLines, boolean truncated) {
    }

    /** Auto-detects the format of every line, with no line limit. */
    public List<LogEvent> parse(String content) {
        return parse(content, null, Integer.MAX_VALUE).events();
    }

    /**
     * Parses at most {@code maxLines} non-blank lines. When the input is longer, the first
     * {@code maxLines} lines are analysed and the result says so, rather than the upload failing.
     *
     * @param forced a format to use for every line, or null to detect it per line
     */
    public ParseResult parse(String content, LogFormat forced, int maxLines) {
        List<LogEvent> events = new ArrayList<>();
        if (content == null || content.isBlank()) {
            return new ParseResult(events, 0, false);
        }

        String trimmed = content.strip();
        boolean documentAllowed = forced == null || forced == LogFormat.CLOUDTRAIL || forced == LogFormat.JSON;
        if (documentAllowed && (trimmed.startsWith("{") || trimmed.startsWith("["))) {
            List<LogEvent> document = parseJsonDocument(trimmed);
            if (document != null) {
                boolean cut = document.size() > maxLines;
                return new ParseResult(cut ? List.copyOf(document.subList(0, maxLines)) : document,
                        document.size(), cut);
            }
        }

        int year = referenceYear(content);
        boolean stacks = forced == null || forced == LogFormat.SPRING_BOOT;

        LogEvent previous = null;
        LogEvent previousLogLine = null;
        int total = 0;
        java.util.Iterator<String> lines = content.lines().iterator();
        while (lines.hasNext()) {
            String line = lines.next();
            if (line.isBlank()) {
                continue;
            }
            total++;
            if (events.size() >= maxLines) {
                continue;
            }
            String text = line.strip();
            LogEvent event;
            try {
                LogEvent stack = stacks && !text.startsWith("{") ? stackLine(text, previous, previousLogLine) : null;
                if (stack != null) {
                    events.add(stack);
                    previous = stack;
                    continue;
                }
                event = forced == null ? parseLine(text, year) : parseLineAs(text, year, forced);
            } catch (RuntimeException malformed) {
                // A line that breaks a parser is kept as plain text; it never fails the upload.
                event = fallback(text, year);
            }
            events.add(event);
            previous = event;
            previousLogLine = event;
        }
        return new ParseResult(events, total, total > events.size());
    }

    /** Parses a line as the given format, or keeps it as an unrecognised line if it does not fit. */
    private LogEvent parseLineAs(String line, int year, LogFormat format) {
        LogEvent event = switch (format) {
            case APACHE -> {
                Matcher web = COMBINED.matcher(line);
                yield web.matches() ? parseLine(line, year) : null;
            }
            case SSH -> sshLine(line, year);
            case SYSLOG -> {
                Matcher header = SYSLOG_HEADER.matcher(line);
                yield header.matches() ? syslog(line, header.group(1), header.group(2), year) : null;
            }
            case JSON -> {
                JsonNode node = jsonObject(line);
                yield node == null ? null : genericJson(node, line);
            }
            case SPRING_BOOT -> springLine(line);
            case WINDOWS_EVENT -> {
                Matcher windows = WIN_EVENT_ID.matcher(line);
                if (windows.find()) {
                    yield windowsText(line, windows.group(1), year);
                }
                LogEvent json = parseJsonLine(line, year);
                yield json != null && json.format() == LogFormat.WINDOWS_EVENT ? json : null;
            }
            case CLOUDTRAIL -> {
                JsonNode node = jsonObject(line);
                yield node != null && node.has("eventName") ? cloudTrail(node, line) : null;
            }
            case FIREWALL -> line.contains("SRC=") ? firewall(line, year) : null;
            case CONTAINER -> {
                JsonNode node = jsonObject(line);
                JsonNode inner = node == null ? null : node.get("log");
                yield inner != null && inner.isTextual()
                        ? dockerJson(node, inner.asText().strip(), line, year)
                        : container(line, containerCategory(line), year);
            }
            case UNKNOWN -> null;
        };
        return event != null ? event : fallback(line, year);
    }

    private JsonNode jsonObject(String line) {
        if (!line.startsWith("{")) {
            return null;
        }
        try {
            JsonNode node = mapper.readTree(line);
            return node != null && node.isObject() ? node : null;
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /** Any line: keep the raw text, the first IPv4 address and a syslog or ISO time if present. */
    private LogEvent fallback(String line, int year) {
        Matcher ip = IPV4.matcher(line);
        Instant when;
        try {
            when = lineTime(line, year);
        } catch (RuntimeException e) {
            when = null;
        }
        return new LogEvent(ip.find() ? ip.group(1) : null, null, null, null, null, false, line, when, null,
                LogFormat.UNKNOWN, null, null, null, null);
    }

    private int referenceYear(String content) {
        java.util.Iterator<String> lines = content.lines().iterator();
        int checked = 0;
        while (lines.hasNext() && checked++ < 5_000) {
            Matcher m = YEAR_HINT.matcher(lines.next());
            if (m.find()) {
                String year = m.group(1) != null ? m.group(1) : m.group(2);
                return Integer.parseInt(year);
            }
        }
        return LocalDateTime.now(clock).getYear();
    }

    private LogEvent parseLine(String line, int year) {
        if (line.startsWith("{") && line.endsWith("}")) {
            LogEvent json = parseJsonLine(line, year);
            if (json != null) {
                return json;
            }
        }

        LogEvent app = springLine(line);
        if (app != null) {
            return app;
        }

        Matcher web = COMBINED.matcher(line);
        if (web.matches()) {
            Integer status = null;
            try {
                status = Integer.valueOf(web.group(5));
            } catch (NumberFormatException ignored) {
                // keep null rather than fail the whole parse
            }
            return new LogEvent(web.group(1), web.group(3), web.group(4), status, web.group(8),
                    false, line, apacheTime(web.group(2)), null,
                    LogFormat.APACHE, null, null, null, null);
        }

        Matcher windows = WIN_EVENT_ID.matcher(line);
        if (windows.find()) {
            return windowsText(line, windows.group(1), year);
        }

        if (line.contains("SRC=") && line.contains("DST=")) {
            return firewall(line, year);
        }

        String containerCategory = containerCategory(line);
        if (containerCategory != null || containsHint(line)) {
            return container(line, containerCategory, year);
        }

        Matcher header = SYSLOG_HEADER.matcher(line);
        if (header.matches() && !header.group(1).startsWith("sshd")) {
            return syslog(line, header.group(1), header.group(2), year);
        }

        LogEvent ssh = sshLine(line, year);
        String lower = line.toLowerCase(Locale.ROOT);
        boolean looksLikeSsh = lower.contains("sshd") || lower.contains("pam_unix") || ssh.user() != null
                || lower.contains("authentication failure");
        return looksLikeSsh ? ssh : ssh.as(LogFormat.UNKNOWN, null);
    }

    /** SSH auth line: failed and accepted logins, the account and the source address. */
    private LogEvent sshLine(String line, int year) {
        Matcher ip = IPV4.matcher(line);
        String address = ip.find() ? ip.group(1) : null;
        boolean failure = hasFailureMarker(line);
        String user = authUser(line);
        String lower = line.toLowerCase(Locale.ROOT);
        String category = failure ? "logon_failure"
                : lower.contains("accepted password") || lower.contains("accepted publickey") ? "logon_success" : null;
        return new LogEvent(address, null, null, null, null, failure, line, lineTime(line, year), user,
                LogFormat.SSH, null, category, null, null);
    }

    // ------------------------------------------------------------ Spring Boot

    private LogEvent springLine(String line) {
        Matcher m = SPRING.matcher(line);
        if (!m.matches()) {
            m = LOGBACK.matcher(line);
            if (!m.matches()) {
                return null;
            }
        }
        String level = m.group(2).toUpperCase(Locale.ROOT);
        if ("WARNING".equals(level)) {
            level = "WARN";
        }
        String message = m.group(3);
        String detail = exceptionName(message);
        boolean error = "ERROR".equals(level) || "FATAL".equals(level);
        String category = detail != null ? "exception" : error ? "app_error" : null;

        return new LogEvent(null, null, null, null, null, hasFailureMarker(message), line,
                instant(m.group(1)), null, LogFormat.SPRING_BOOT, level, category, detail, null);
    }

    /**
     * Stack-trace lines carry no time of their own, so they inherit the previous event's. An
     * exception header that repeats the exception already named on the log line above is not
     * counted twice.
     */
    /**
     * Whether the text from {@code from} up to the first ":" is short enough to be a class name.
     * The stack-trace patterns repeat a group per package segment, and Java's regex engine uses a
     * stack frame per repetition, so a crafted name with thousands of segments would overflow it.
     */
    private static boolean classNameFits(String line, int from) {
        int colon = line.indexOf(':', from);
        return (colon < 0 ? line.length() : colon) - from <= MAX_CLASS_NAME;
    }

    private LogEvent stackLine(String line, LogEvent previous, LogEvent previousLogLine) {
        boolean afterJava = previous != null && previous.format() == LogFormat.SPRING_BOOT;

        Matcher header = EXCEPTION_HEADER.matcher(line);
        if (classNameFits(line, 0) && header.matches()) {
            String name = header.group(1);
            boolean alreadyCounted = afterJava && previousLogLine != null
                    && name.equals(previousLogLine.detail()) && previous == previousLogLine;
            return stackEvent(line, previous, alreadyCounted ? "stack_frame" : "exception", name);
        }
        if (!afterJava) {
            return null;
        }
        Matcher cause = CAUSED_BY.matcher(line);
        if (classNameFits(line, CAUSED_BY_PREFIX.length()) && cause.matches()) {
            return stackEvent(line, previous, "caused_by", cause.group(1));
        }
        if (STACK_FRAME.matcher(line).matches()) {
            return stackEvent(line, previous, "stack_frame", null);
        }
        return null;
    }

    private static LogEvent stackEvent(String line, LogEvent previous, String category, String detail) {
        return new LogEvent(null, null, null, null, null, false, line,
                previous == null ? null : previous.timestamp(), null, LogFormat.SPRING_BOOT,
                null, category, detail, null);
    }

    // ----------------------------------------------------------------- Syslog

    /**
     * "alice : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/ls" gives [alice, /bin/ls]: the
     * first word must be followed by " : ", and the command is everything after the last
     * "COMMAND=". Plain text search, so a crafted line can't make it slow.
     */
    static String[] sudoCommand(String message) {
        int start = 0;
        while (start < message.length() && Character.isWhitespace(message.charAt(start))) {
            start++;
        }
        int separator = message.indexOf(SUDO_SEPARATOR, start);
        if (separator <= start) {
            return null;
        }
        for (int i = start; i < separator; i++) {
            if (Character.isWhitespace(message.charAt(i))) {
                return null;
            }
        }
        int command = message.lastIndexOf(SUDO_COMMAND);
        if (command < separator + SUDO_SEPARATOR.length()) {
            return null;
        }
        return new String[] {message.substring(start, separator), message.substring(command + SUDO_COMMAND.length())};
    }

    /**
     * The first fully qualified exception name in a message, e.g. "java.io.IOException": package
     * parts, then a capitalised class part ending in "Exception" or "Error". Each dotted word is
     * checked once, part by part, with no regex backtracking. Like the greedy pattern it replaces,
     * it takes the longest name, so "a.FooException.BarError" gives the whole word.
     */
    static String exceptionName(String message) {
        Matcher word = DOTTED_WORD.matcher(message);
        while (word.find()) {
            if (word.end() - word.start() > MAX_CLASS_NAME) {
                continue;
            }
            String name = exceptionNameAtStart(word.group());
            if (name != null) {
                return name;
            }
        }
        return null;
    }

    private static String exceptionNameAtStart(String word) {
        String[] parts = word.split("\\.", -1);
        int validPrefix = 0;  // how many leading parts are identifiers
        while (validPrefix < parts.length && isIdentifier(parts[validPrefix])) {
            validPrefix++;
        }
        // Part i is the class; parts 0..i-1 must be identifiers. Prefer the longest name.
        for (int i = Math.min(validPrefix, parts.length - 1); i >= 1; i--) {
            if (isExceptionClass(parts[i])) {
                return String.join(".", java.util.Arrays.copyOfRange(parts, 0, i + 1));
            }
        }
        return null;
    }

    /** "IOException", "OutOfMemoryError": capitalised, with at least one character before the suffix. */
    private static boolean isExceptionClass(String part) {
        return isIdentifier(part) && part.charAt(0) >= 'A' && part.charAt(0) <= 'Z'
                && (endsWithAfterSomething(part, "Exception") || endsWithAfterSomething(part, "Error"));
    }

    private static boolean endsWithAfterSomething(String text, String suffix) {
        return text.length() > suffix.length() && text.endsWith(suffix);
    }

    /** Java-style identifier in ASCII: a letter, "_" or "$", then letters, digits, "_" or "$". */
    private static boolean isIdentifier(String part) {
        if (part.isEmpty() || !(isAsciiLetter(part.charAt(0)) || part.charAt(0) == '_' || part.charAt(0) == '$')) {
            return false;
        }
        for (int i = 1; i < part.length(); i++) {
            char c = part.charAt(i);
            if (!(isAsciiLetter(c) || (c >= '0' && c <= '9') || c == '_' || c == '$')) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAsciiLetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private LogEvent syslog(String line, String program, String message, int year) {
        String prog = program.toLowerCase(Locale.ROOT);
        String lower = message.toLowerCase(Locale.ROOT);
        String category = null;
        String user = null;
        String detail = null;
        boolean failure = false;

        if (prog.startsWith("sudo")) {
            String[] cmd = sudoCommand(message);
            if (lower.contains("incorrect password attempt") || lower.contains("authentication failure")) {
                category = "sudo_failure";
                failure = true;
                user = cmd != null ? cmd[0] : group(PAM_USER, message);
                if (user == null) {
                    user = message.strip().split("\\s+")[0];
                }
            } else if (cmd != null) {
                category = "sudo_command";
                user = cmd[0];
                detail = cmd[1].strip();
            }
        } else if (prog.startsWith("su")) {
            if (lower.contains("failed su") || lower.contains("authentication failure")) {
                category = "su_failure";
                failure = true;
                Matcher target = SU_TARGET.matcher(message);
                user = target.find() ? firstNonNull(target, 2, 4, 6) : group(PAM_USER, message);
            } else {
                Matcher target = SU_TARGET.matcher(message);
                if (target.find()) {
                    category = "su_session";
                    user = firstNonNull(target, 2, 4, 6);
                    detail = firstNonNull(target, 1, 3, 5);
                }
            }
        } else if (prog.startsWith("useradd") || prog.startsWith("adduser")) {
            Matcher m = NEW_USER.matcher(message);
            if (m.find()) {
                category = "account_created";
                user = m.group(1);
            }
        } else if (prog.startsWith("usermod") || prog.startsWith("gpasswd")) {
            Matcher m = GROUP_ADD.matcher(message);
            if (m.find() && PRIVILEGED_GROUPS.contains(m.group(2))) {
                category = "added_to_group";
                user = m.group(1);
                detail = m.group(2);
            }
        }
        if (category == null && hasFailureMarker(message)) {
            failure = true;
            category = "logon_failure";
        }

        Matcher ip = IPV4.matcher(message);
        return new LogEvent(ip.find() ? ip.group(1) : null, null, null, null, null, failure, line,
                lineTime(line, year), user, LogFormat.SYSLOG, null, category, detail, null);
    }

    private static String firstNonNull(Matcher m, int... groups) {
        for (int g : groups) {
            if (m.group(g) != null) {
                return m.group(g);
            }
        }
        return null;
    }

    // ---------------------------------------------------------------- Windows

    private LogEvent windowsText(String line, String id, int year) {
        String user = null;
        Matcher member = WIN_MEMBER.matcher(line);
        if (member.find()) {
            user = member.group(1);
        } else {
            Matcher users = WIN_USER.matcher(line);
            while (users.find()) {
                if (!"-".equals(users.group(1))) {
                    user = users.group(1);
                }
            }
        }
        if (user == null) {
            Matcher subject = WIN_SUBJECT.matcher(line);
            if (subject.find() && !"-".equals(subject.group(1))) {
                user = subject.group(1);
            }
        }
        Matcher ipMatch = WIN_IP.matcher(line);
        String ip = null;
        if (ipMatch.find() && !"-".equals(ipMatch.group(1))) {
            ip = ipMatch.group(1);
        }
        return windowsEvent(id, user, ip, lineTime(line, year), line);
    }

    private static LogEvent windowsEvent(String id, String user, String ip, Instant when, String raw) {
        String category = WINDOWS_CATEGORIES.get(id);
        return new LogEvent(ip, null, null, null, null, "logon_failure".equals(category), raw,
                when, user, LogFormat.WINDOWS_EVENT, null, category, id, null);
    }

    // --------------------------------------------------------------- Firewall

    private LogEvent firewall(String line, int year) {
        String src = group(FW_SRC, line);
        String dst = group(FW_DST, line);
        Integer port = null;
        String dpt = group(FW_DPT, line);
        if (dpt != null) {
            port = Integer.valueOf(dpt);
        }
        boolean blocked = FW_BLOCK.matcher(line).find();
        return new LogEvent(src, null, null, null, null, false, line, lineTime(line, year), null,
                LogFormat.FIREWALL, null, blocked ? "firewall_block" : "firewall_allow", dst, port);
    }

    // -------------------------------------------------------------- Container

    private static String containerCategory(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String> marker : CONTAINER_MARKERS.entrySet()) {
            if (lower.contains(marker.getKey())) {
                // "evicted" is a common English word; only trust it with a container hint.
                if ("evicted".equals(marker.getValue()) && !containsHint(text) && !lower.contains("pod")) {
                    continue;
                }
                return marker.getValue();
            }
        }
        return null;
    }

    private static boolean containsHint(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        return CONTAINER_HINTS.stream().anyMatch(lower::contains);
    }

    private LogEvent container(String line, String category, int year) {
        String workload = null;
        Matcher m = WORKLOAD.matcher(line);
        if (m.find()) {
            for (int g = 1; g <= m.groupCount() && workload == null; g++) {
                workload = m.group(g);
            }
        }
        return new LogEvent(null, null, null, null, null, false, line, lineTime(line, year), null,
                LogFormat.CONTAINER, null, category, workload, null);
    }

    // ------------------------------------------------------------------- JSON

    /** A whole-file JSON document: a CloudTrail {"Records": [...]} file or a JSON array of events. */
    private List<LogEvent> parseJsonDocument(String content) {
        JsonNode root;
        try {
            root = strictReader.readValue(content);
        } catch (Exception e) {
            return null;
        }
        JsonNode records = root.isObject() ? root.get("Records") : root;
        if (records == null || !records.isArray()) {
            return null;
        }
        int year = LocalDateTime.now(clock).getYear();
        List<LogEvent> events = new ArrayList<>();
        for (JsonNode node : records) {
            if (node.isObject()) {
                events.add(fromJson(node, node.toString(), year));
            }
        }
        return events;
    }

    private LogEvent parseJsonLine(String line, int year) {
        try {
            JsonNode node = mapper.readTree(line);
            if (node == null || !node.isObject()) {
                return null;
            }
            return fromJson(node, line, year);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    private LogEvent fromJson(JsonNode node, String raw, int year) {
        if (node.has("eventName") && node.has("eventSource")) {
            return cloudTrail(node, raw);
        }
        JsonNode winlog = node.get("winlog");
        String windowsId = text(node, "EventID", "EventId", "event_id", "EventCode");
        if (windowsId == null && winlog != null) {
            windowsId = text(winlog, "event_id");
        }
        if (windowsId != null && (winlog != null || node.has("TimeCreated") || node.has("EventData")
                || node.has("Channel") || node.has("ProviderName") || node.has("TargetUserName"))) {
            return windowsJson(node, winlog, windowsId, raw);
        }
        JsonNode inner = node.get("log");
        if (inner != null && inner.isTextual() && (node.has("stream") || node.has("time"))) {
            return dockerJson(node, inner.asText().strip(), raw, year);
        }
        return genericJson(node, raw);
    }

    private LogEvent genericJson(JsonNode node, String raw) {
        String ip = text(node, "remote_addr", "remote_ip", "client_ip", "clientip",
                "ip", "src_ip", "source_ip");
        String method = text(node, "method", "request_method", "http_method");
        String path = text(node, "path", "uri", "request_uri", "url");

        String request = text(node, "request");
        if (request != null && (method == null || path == null)) {
            String[] parts = request.split(" ");
            if (parts.length >= 2) {
                method = method == null ? parts[0] : method;
                path = path == null ? parts[1] : path;
            }
        }

        Integer status = integer(node, "status", "status_code", "response_code");
        String userAgent = text(node, "user_agent", "http_user_agent", "useragent", "ua");
        String user = text(node, "user", "username", "user_name");
        Instant when = instant(text(node, "time", "timestamp", "@timestamp", "ts",
                "time_iso8601", "datetime"));
        String level = text(node, "level", "severity", "log.level");
        String message = text(node, "message", "msg");

        if (ip == null) {
            Matcher m = IPV4.matcher(raw);
            ip = m.find() ? m.group(1) : null;
        }

        String category = null;
        String detail = null;
        if (level != null) {
            level = level.toUpperCase(Locale.ROOT);
            if (message != null) {
                detail = exceptionName(message);
            }
            boolean error = "ERROR".equals(level) || "FATAL".equals(level);
            category = detail != null ? "exception" : error ? "app_error" : null;
        }
        boolean failure = hasFailureMarker(raw);
        if (category == null && failure) {
            category = "logon_failure";
        }

        return new LogEvent(ip, method, path, status, userAgent, failure, raw, when, user,
                LogFormat.JSON, level, category, detail, null);
    }

    private LogEvent cloudTrail(JsonNode node, String raw) {
        String eventName = text(node, "eventName");
        String source = text(node, "eventSource");
        JsonNode identity = node.get("userIdentity");
        String identityType = identity == null ? null : text(identity, "type");
        String user = null;
        if ("Root".equals(identityType)) {
            user = "root";
        } else if (identity != null) {
            user = text(identity, "userName");
            JsonNode issuer = identity.path("sessionContext").path("sessionIssuer");
            if (user == null && issuer.isObject()) {
                user = text(issuer, "userName");
            }
            String arn = text(identity, "arn");
            if (user == null && arn != null) {
                user = arn.substring(arn.lastIndexOf('/') + 1);
            }
        }

        String sourceIp = text(node, "sourceIPAddress");
        String ip = sourceIp != null && IPV4.matcher(sourceIp).matches() ? sourceIp : null;
        if (ip == null && sourceIp != null && sourceIp.contains(":") && !sourceIp.contains(".amazonaws.com")) {
            ip = sourceIp;
        }

        String category = null;
        boolean failure = false;
        String errorCode = text(node, "errorCode");
        if ("ConsoleLogin".equals(eventName)) {
            String outcome = text(node.path("responseElements"), "ConsoleLogin");
            if ("Failure".equalsIgnoreCase(outcome) || text(node, "errorMessage") != null) {
                category = "console_login_failure";
                failure = true;
            } else {
                String mfa = text(node.path("additionalEventData"), "MFAUsed");
                category = "No".equalsIgnoreCase(mfa) ? "console_login_no_mfa" : "console_login";
            }
        } else if (eventName != null && LOGGING_DISABLED.contains(eventName)) {
            category = "logging_disabled";
        } else if ("iam.amazonaws.com".equals(source) && eventName != null
                && IAM_CHANGE_PREFIXES.stream().anyMatch(eventName::startsWith)) {
            category = "iam_change";
        } else if (errorCode != null && (errorCode.contains("AccessDenied") || errorCode.contains("Unauthorized"))) {
            category = "access_denied";
        } else if (eventName != null && errorCode == null && DELETE_PREFIXES.stream().anyMatch(eventName::startsWith)) {
            category = "resource_deleted";
        }

        return new LogEvent(ip, null, null, null, text(node, "userAgent"), failure, raw,
                instant(text(node, "eventTime")), user, LogFormat.CLOUDTRAIL, null,
                category, eventName, null);
    }

    private LogEvent windowsJson(JsonNode node, JsonNode winlog, String id, String raw) {
        JsonNode data = node.has("EventData") ? node.get("EventData")
                : winlog != null && winlog.has("event_data") ? winlog.get("event_data") : node;
        String user = text(data, "TargetUserName", "MemberName", "SubjectUserName");
        if (user == null) {
            user = text(node, "TargetUserName", "SubjectUserName");
        }
        String ip = text(data, "IpAddress");
        if (ip == null) {
            ip = text(node, "IpAddress");
        }
        if ("-".equals(ip)) {
            ip = null;
        }
        if ("-".equals(user)) {
            user = null;
        }
        Instant when = instant(text(node, "TimeCreated", "@timestamp", "timestamp", "time"));
        return windowsEvent(id, user, ip, when, raw);
    }

    private LogEvent dockerJson(JsonNode node, String message, String raw, int year) {
        Instant time = instant(text(node, "time"));
        LogEvent inner = parseLine(message, year);
        String category = inner.category() != null ? inner.category() : containerCategory(message);
        return new LogEvent(inner.ip(), inner.method(), inner.path(), inner.status(), inner.userAgent(),
                inner.authFailure(), raw, inner.timestamp() != null ? inner.timestamp() : time, inner.user(),
                LogFormat.CONTAINER, inner.level(), category, inner.detail(), inner.port());
    }

    private static String text(JsonNode node, String... keys) {
        if (node == null) {
            return null;
        }
        for (String key : keys) {
            JsonNode value = node.get(key);
            if (value != null && !value.isNull() && !value.isContainerNode()) {
                String text = value.asText();
                if (!text.isBlank()) {
                    return text;
                }
            }
        }
        return null;
    }

    private static Integer integer(JsonNode node, String... keys) {
        for (String key : keys) {
            JsonNode value = node.get(key);
            if (value == null || value.isNull()) {
                continue;
            }
            if (value.isNumber()) {
                return value.asInt();
            }
            try {
                return Integer.valueOf(value.asText().trim());
            } catch (NumberFormatException ignored) {
                // try the next key
            }
        }
        return null;
    }

    private static String group(Pattern pattern, String line) {
        Matcher m = pattern.matcher(line);
        return m.find() ? m.group(1) : null;
    }

    // ------------------------------------------------------------------- time

    /** Syslog time first, then an ISO time anywhere in the line, then a US date. */
    private static Instant lineTime(String line, int year) {
        Instant syslog = syslogTime(line, year);
        if (syslog != null) {
            return syslog;
        }
        Matcher iso = ISO_TIME.matcher(line);
        if (iso.find()) {
            Instant t = instant(iso.group(1));
            if (t != null) {
                return t;
            }
        }
        Matcher us = US_TIME.matcher(line);
        if (us.find()) {
            try {
                int hour = Integer.parseInt(us.group(4));
                if ("PM".equals(us.group(7)) && hour < 12) {
                    hour += 12;
                } else if ("AM".equals(us.group(7)) && hour == 12) {
                    hour = 0;
                }
                return LocalDateTime.of(Integer.parseInt(us.group(3)), Integer.parseInt(us.group(1)),
                        Integer.parseInt(us.group(2)), hour, Integer.parseInt(us.group(5)),
                        Integer.parseInt(us.group(6))).toInstant(ZoneOffset.UTC);
            } catch (DateTimeException ignored) {
                return null;
            }
        }
        return null;
    }

    private static Instant apacheTime(String value) {
        try {
            return OffsetDateTime.parse(value, APACHE_TIME).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static Instant syslogTime(String line, int year) {
        Matcher m = SYSLOG_TIME.matcher(line);
        if (!m.find()) {
            return null;
        }
        int month = MONTHS.indexOf(m.group(1).toLowerCase(Locale.ROOT)) + 1;
        if (month == 0) {
            return null;
        }
        try {
            return LocalDateTime.of(year, month, Integer.parseInt(m.group(2)),
                    Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)),
                    Integer.parseInt(m.group(5))).toInstant(ZoneOffset.UTC);
        } catch (DateTimeException e) {
            return null;
        }
    }

    /** ISO-8601 with or without zone (UTC assumed), space or T separator, comma millis, or epoch. */
    static Instant instant(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        try {
            return Instant.parse(v);
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        try {
            return OffsetDateTime.parse(v).toInstant();
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        try {
            return OffsetDateTime.parse(v, APACHE_TIME).toInstant();
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        String iso = v.replace(' ', 'T').replace(',', '.');
        Matcher compact = COMPACT_OFFSET.matcher(iso);
        if (compact.find()) {
            iso = iso.substring(0, compact.start()) + compact.group(1) + ":" + compact.group(2);
        }
        try {
            return OffsetDateTime.parse(iso).toInstant();
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        try {
            return LocalDateTime.parse(iso).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException ignored) {
            // try the next form
        }
        try {
            double number = Double.parseDouble(v);
            // Epoch seconds or milliseconds up to the year 9999; anything else (NaN, infinity,
            // negative or absurdly large values from the uploaded file) is not a timestamp.
            if (!(number >= 0 && number <= MAX_EPOCH_MILLIS)) {
                return null;
            }
            long whole = (long) number;
            return whole > 100_000_000_000L ? Instant.ofEpochMilli(whole) : Instant.ofEpochSecond(whole);
        } catch (NumberFormatException | DateTimeException ignored) {
            return null;
        }
    }

    // ------------------------------------------------------------------- auth

    private static boolean hasFailureMarker(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        for (String marker : AUTH_FAILURE_MARKERS) {
            if (lower.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private static String authUser(String line) {
        Matcher m = AUTH_USER.matcher(line);
        if (m.find()) {
            return m.group(1);
        }
        Matcher invalid = INVALID_USER.matcher(line);
        return invalid.find() ? invalid.group(1) : null;
    }
}
