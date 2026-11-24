package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogFormat;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogFormatDetectionTest {

    private final LogParser parser = new LogParser();

    private LogEvent one(String line) {
        List<LogEvent> events = parser.parse(line);
        assertEquals(1, events.size());
        return events.get(0);
    }

    @Test
    void recognisesWebAndSshLines() {
        assertEquals(LogFormat.APACHE, one("203.0.113.45 - - [12/Nov/2026:08:09:03 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"ua\"").format());
        assertEquals(LogFormat.SSH, one("Nov 12 03:20:11 web01 sshd[2411]: Failed password for root from 1.2.3.4 port 22 ssh2").format());
        assertEquals(LogFormat.JSON, one("{\"remote_addr\":\"1.2.3.4\",\"uri\":\"/\",\"status\":200}").format());
        assertEquals(LogFormat.UNKNOWN, one("hello world from 10.0.0.1").format());
    }

    @Test
    void readsWindowsKeyValueEvents() {
        LogEvent e = one("2026-11-12T02:10:00Z DC01 Microsoft-Windows-Security-Auditing EventID=4625 "
                + "TargetUserName=administrator IpAddress=203.0.113.77 Message=\"An account failed to log on.\"");

        assertEquals(LogFormat.WINDOWS_EVENT, e.format());
        assertEquals("logon_failure", e.category());
        assertTrue(e.authFailure());
        assertEquals("administrator", e.user());
        assertEquals("203.0.113.77", e.ip());
        assertEquals("4625", e.detail());
        assertEquals(Instant.parse("2026-11-12T02:10:00Z"), e.timestamp());
    }

    @Test
    void readsEventViewerTextAndPrefersTheGroupMember() {
        LogEvent lockout = one("Audit Failure,11/12/2026 2:45:10 PM,Microsoft-Windows-Security-Auditing,4740,"
                + "User Account Management,A user account was locked out. Account Name: jdoe");
        assertEquals("account_lockout", lockout.category());
        assertEquals("jdoe", lockout.user());
        assertEquals(Instant.parse("2026-11-12T14:45:10Z"), lockout.timestamp());

        LogEvent group = one("EventID=4732 SubjectUserName=svc MemberName=helpdesk2 TargetUserName=Administrators");
        assertEquals("added_to_group", group.category());
        assertEquals("helpdesk2", group.user());

        LogEvent cleared = one("2026-11-12T02:41:02Z DC01 EventID=1102 SubjectUserName=helpdesk2");
        assertEquals("audit_log_cleared", cleared.category());
        assertEquals("helpdesk2", cleared.user());
    }

    @Test
    void readsWinlogbeatJson() {
        LogEvent e = one("{\"@timestamp\":\"2026-11-12T02:10:00Z\",\"winlog\":{\"event_id\":4624,"
                + "\"event_data\":{\"TargetUserName\":\"svc_sql\",\"IpAddress\":\"203.0.113.77\"}}}");

        assertEquals(LogFormat.WINDOWS_EVENT, e.format());
        assertEquals("logon_success", e.category());
        assertEquals("svc_sql", e.user());
        assertEquals("203.0.113.77", e.ip());
    }

    @Test
    void readsACloudTrailDocument() {
        String doc = "{\"Records\":["
                + "{\"eventTime\":\"2026-11-12T06:05:40Z\",\"eventSource\":\"signin.amazonaws.com\",\"eventName\":\"ConsoleLogin\","
                + "\"sourceIPAddress\":\"203.0.113.200\",\"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"alice\"},"
                + "\"responseElements\":{\"ConsoleLogin\":\"Success\"},\"additionalEventData\":{\"MFAUsed\":\"No\"}},"
                + "{\"eventTime\":\"2026-11-12T06:07:02Z\",\"eventSource\":\"iam.amazonaws.com\",\"eventName\":\"CreateAccessKey\","
                + "\"sourceIPAddress\":\"203.0.113.200\",\"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"alice\"}},"
                + "{\"eventTime\":\"2026-11-12T06:09:15Z\",\"eventSource\":\"cloudtrail.amazonaws.com\",\"eventName\":\"StopLogging\","
                + "\"sourceIPAddress\":\"cloudtrail.amazonaws.com\",\"userIdentity\":{\"type\":\"Root\"}}"
                + "]}";

        List<LogEvent> events = parser.parse(doc);

        assertEquals(3, events.size());
        assertTrue(events.stream().allMatch(e -> e.format() == LogFormat.CLOUDTRAIL));
        assertEquals("console_login_no_mfa", events.get(0).category());
        assertEquals("alice", events.get(0).user());
        assertEquals("iam_change", events.get(1).category());
        assertEquals("logging_disabled", events.get(2).category());
        assertEquals("root", events.get(2).user());
        assertNull(events.get(2).ip(), "a service hostname is not an address");
    }

    @Test
    void readsCloudTrailEventsOnePerLineAndFailedConsoleLogins() {
        LogEvent e = one("{\"eventTime\":\"2026-11-12T06:00:12Z\",\"eventSource\":\"signin.amazonaws.com\","
                + "\"eventName\":\"ConsoleLogin\",\"sourceIPAddress\":\"203.0.113.200\",\"userIdentity\":{\"type\":\"IAMUser\","
                + "\"userName\":\"alice\"},\"responseElements\":{\"ConsoleLogin\":\"Failure\"}}");

        assertEquals(LogFormat.CLOUDTRAIL, e.format());
        assertTrue(e.authFailure());
        assertEquals("console_login_failure", e.category());
    }

    @Test
    void aJsonLinesFileIsNotMistakenForOneDocument() {
        List<LogEvent> events = parser.parse("{\"ip\":\"1.1.1.1\",\"status\":200}\n{\"ip\":\"2.2.2.2\",\"status\":404}");
        assertEquals(2, events.size());
        assertEquals("2.2.2.2", events.get(1).ip());
    }

    @Test
    void readsUfwFirewallLines() {
        LogEvent e = one("Nov 12 04:10:03 web01 kernel: [812000.512] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.150 "
                + "DST=192.0.2.20 LEN=44 PROTO=TCP SPT=50000 DPT=3389 WINDOW=1024 SYN URGP=0");

        assertEquals(LogFormat.FIREWALL, e.format());
        assertEquals("firewall_block", e.category());
        assertEquals("203.0.113.150", e.ip());
        assertEquals("192.0.2.20", e.detail());
        assertEquals(3389, e.port());
        assertNull(e.method(), "firewall events are not web requests");

        assertEquals("firewall_allow", one("Nov 12 04:10:03 h kernel: [UFW ALLOW] IN=eth0 SRC=1.1.1.1 DST=2.2.2.2 DPT=443").category());
    }

    @Test
    void readsSpringBootLinesAndStackTracesWithoutDoubleCounting() {
        String log = String.join("\n",
                "2026-11-12T09:13:00.120Z ERROR 4211 --- [orders] [exec-1] o.a.c.c.DispatcherServlet : Servlet.service() threw exception",
                "org.springframework.dao.DataAccessResourceFailureException: Unable to acquire JDBC Connection",
                "\tat com.example.OrderService.find(OrderService.java:58)",
                "Caused by: java.sql.SQLTransientConnectionException: Connection is not available",
                "\t... 87 common frames omitted",
                "2026-11-12 09:14:00,500 [main] WARN  com.zaxxer.hikari.Pool - Failed to validate connection",
                "2026-11-12T09:15:00Z ERROR 1 --- [x] c.e.Handler : Unhandled: java.lang.NullPointerException: boom",
                "java.lang.NullPointerException: boom");

        List<LogEvent> events = parser.parse(log);

        assertEquals(8, events.size());
        assertTrue(events.stream().allMatch(e -> e.format() == LogFormat.SPRING_BOOT));
        assertEquals("ERROR", events.get(0).level());
        assertEquals("app_error", events.get(0).category());
        assertEquals("exception", events.get(1).category());
        assertEquals("org.springframework.dao.DataAccessResourceFailureException", events.get(1).detail());
        assertNull(events.get(1).level(), "stack lines are not log lines");
        assertEquals(Instant.parse("2026-11-12T09:13:00.120Z"), events.get(2).timestamp());
        assertEquals("stack_frame", events.get(2).category());
        assertEquals("caused_by", events.get(3).category());
        assertEquals("java.sql.SQLTransientConnectionException", events.get(3).detail());
        assertEquals("WARN", events.get(5).level());
        assertEquals(Instant.parse("2026-11-12T09:14:00.500Z"), events.get(5).timestamp());
        assertEquals("exception", events.get(6).category());
        assertEquals("stack_frame", events.get(7).category(), "header repeating the line above is not counted again");
    }

    @Test
    void readsKubernetesAndDockerLines() {
        LogEvent crash = one("2026-11-12T11:04:30Z Warning BackOff pod/payments-7d9f8c6b5-x2k4p "
                + "Back-off restarting failed container payments");
        assertEquals(LogFormat.CONTAINER, crash.format());
        assertEquals("crash_loop", crash.category());
        assertEquals("payments-7d9f8c6b5-x2k4p", crash.detail());

        LogEvent oom = one("Nov 12 11:20:41 node-2 kernel: Memory cgroup out of memory: Killed process 30211 (java) total-vm:4123456kB");
        assertEquals("oom_kill", oom.category());
        assertEquals("java", oom.detail());

        LogEvent docker = one("{\"log\":\"2026-11-12T11:40:01.311Z ERROR 1 --- [p] [main] o.s.b.SpringApplication : "
                + "failed: java.lang.IllegalStateException: Missing key\\n\",\"stream\":\"stderr\",\"time\":\"2026-11-12T11:40:01.311Z\"}");
        assertEquals(LogFormat.CONTAINER, docker.format());
        assertEquals("exception", docker.category());
        assertEquals("java.lang.IllegalStateException", docker.detail());

        assertEquals(LogFormat.UNKNOWN, one("The tenant was evicted from the flat").format());
    }

    @Test
    void reportsTheDominantFormatOrAMix() {
        Map<LogFormat, Integer> counts = new EnumMap<>(LogFormat.class);
        counts.put(LogFormat.FIREWALL, 90);
        counts.put(LogFormat.UNKNOWN, 400);
        counts.put(LogFormat.SSH, 10);
        assertEquals("UFW / iptables firewall", LogAnalysisService.detectedFormat(counts));

        counts.put(LogFormat.SSH, 60);
        assertEquals("Mixed: UFW / iptables firewall, SSH auth", LogAnalysisService.detectedFormat(counts));

        assertEquals("Unrecognised", LogAnalysisService.detectedFormat(Map.of(LogFormat.UNKNOWN, 3)));
        assertFalse(LogAnalysisService.detectedFormat(Map.of()).isBlank());
    }

    @Test
    void readsLinuxSyslogSudoSuAndAccountChanges() {
        LogEvent sudo = one("Nov 12 09:47:55 app01 sudo:      bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash");
        assertEquals(LogFormat.SYSLOG, sudo.format());
        assertEquals("sudo_command", sudo.category());
        assertEquals("bob", sudo.user());
        assertEquals("/bin/bash", sudo.detail());

        LogEvent sudoFail = one("Nov 12 09:40:09 app01 sudo: www-data : 3 incorrect password attempts ; TTY=pts/2 ; "
                + "PWD=/var/www ; USER=root ; COMMAND=/bin/bash");
        assertEquals("sudo_failure", sudoFail.category());
        assertEquals("www-data", sudoFail.user());
        assertTrue(sudoFail.authFailure());

        LogEvent su = one("Nov 12 09:50:03 app01 su: pam_unix(su-l:session): session opened for user root(uid=0) by bob(uid=1001)");
        assertEquals("su_session", su.category());
        assertEquals("bob", su.user());
        assertEquals("root", su.detail());

        assertEquals("su_failure", one("Nov 12 09:41:31 app01 su: FAILED SU (to root) www-data on pts/2").category());

        LogEvent created = one("Nov 12 09:48:20 app01 useradd[5120]: new user: name=sysupdate, UID=1005, GID=1005");
        assertEquals("account_created", created.category());
        assertEquals("sysupdate", created.user());

        LogEvent group = one("Nov 12 09:48:41 app01 usermod[5133]: add 'sysupdate' to group 'sudo'");
        assertEquals("added_to_group", group.category());
        assertEquals("sudo", group.detail());
        assertNull(one("Nov 12 09:48:41 app01 usermod[5133]: add 'sysupdate' to shadow group 'sudo'").category(),
                "the shadow-group line repeats the same change");
        assertNull(one("Nov 12 09:48:41 app01 usermod[5133]: add 'x' to group 'audio'").category());

        assertEquals(LogFormat.SYSLOG, one("Nov 12 10:00:01 app01 systemd[1]: Started Daily apt download activities.").format());
        assertEquals(LogFormat.SSH, one("Nov 12 03:22:07 web01 sshd[2430]: Accepted password for admin from 1.2.3.4 port 5 ssh2").format());
    }

    @Test
    void sshSuccessfulLoginsAreCategorised() {
        assertEquals("logon_success",
                one("Nov 12 07:58:40 web01 sshd[3001]: Accepted publickey for deploy from 192.168.1.31 port 5 ssh2").category());
    }

    @Test
    void cloudTrailDeletionsAreRecognisedButFailedDeletesAreNot() {
        LogEvent deleted = one("{\"eventName\":\"DeleteBucket\",\"eventSource\":\"s3.amazonaws.com\",\"userIdentity\":{\"userName\":\"alice\"}}");
        assertEquals("resource_deleted", deleted.category());
        assertEquals("DeleteBucket", deleted.detail());

        LogEvent denied = one("{\"eventName\":\"DeleteBucket\",\"eventSource\":\"s3.amazonaws.com\",\"errorCode\":\"AccessDenied\"}");
        assertEquals("access_denied", denied.category());

        assertEquals("iam_change", one("{\"eventName\":\"DeleteUser\",\"eventSource\":\"iam.amazonaws.com\"}").category());
    }
}
