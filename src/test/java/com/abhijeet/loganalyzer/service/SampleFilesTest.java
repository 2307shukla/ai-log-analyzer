package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.Finding;
import com.abhijeet.loganalyzer.model.LogSummary;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every bundled sample is detected as its format and produces the findings it was written to show. */
class SampleFilesTest {

    private final LogParser parser = new LogParser();
    private final LogAnalysisService service = new LogAnalysisService(null);

    private LogSummary summarize(String resource) throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/" + resource)) {
            assertNotNull(in, resource + " is on the classpath");
            return service.summarize(parser.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
        }
    }

    private void check(String resource, String format, String level, String... rules) throws Exception {
        LogSummary s = summarize(resource);
        assertEquals(format, s.detectedFormat(), resource);
        assertEquals(level, s.riskLevel(), resource);
        Set<String> found = s.findings().stream().map(Finding::rule).collect(Collectors.toSet());
        assertTrue(found.containsAll(List.of(rules)), resource + " found " + found);
        s.findings().forEach(f -> assertEquals(MitreMapping.technique(f.rule()), f.mitre(), f.rule()));
    }

    @Test
    void apache() throws Exception {
        check("samples/apache-access.log", "Apache / Nginx access", "CRITICAL",
                "WEB_LOGIN_BRUTE_FORCE", "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "SCANNER_USER_AGENT",
                "SENSITIVE_PATH_PROBING");
    }

    @Test
    void ssh() throws Exception {
        check("samples/ssh-auth.log", "SSH auth", "CRITICAL",
                "BRUTE_FORCE", "PASSWORD_SPRAYING", "COMPROMISED_LOGIN", "SSH_ROOT_LOGIN");
    }

    @Test
    void syslog() throws Exception {
        check("samples/linux-syslog.log", "Linux syslog", "HIGH",
                "SUDO_SU_USAGE", "SUDO_SU_FAILURES", "ACCOUNT_CREATED", "PRIVILEGED_GROUP_CHANGE");
    }

    @Test
    void jsonLines() throws Exception {
        check("samples/json-lines.jsonl", "JSON lines", "CRITICAL", "SQL_INJECTION", "PATH_TRAVERSAL", "BRUTE_FORCE");
    }

    @Test
    void springBoot() throws Exception {
        check("samples/spring-boot.log", "Spring Boot / Java", "MEDIUM", "APP_EXCEPTIONS", "ERROR_BURST");
    }

    @Test
    void windows() throws Exception {
        check("samples/windows-security.log", "Windows Security Event", "CRITICAL",
                "BRUTE_FORCE", "COMPROMISED_LOGIN", "ACCOUNT_CREATED", "PRIVILEGED_GROUP_CHANGE",
                "AUDIT_LOG_CLEARED", "PRIVILEGE_USE", "ACCOUNT_LOCKOUT");
    }

    @Test
    void cloudTrail() throws Exception {
        check("samples/cloudtrail.json", "AWS CloudTrail", "CRITICAL",
                "CONSOLE_LOGIN_WITHOUT_MFA", "ROOT_ACCOUNT_USAGE", "IAM_CHANGES", "DELETED_RESOURCES",
                "CLOUD_LOGGING_DISABLED", "COMPROMISED_LOGIN");
    }

    @Test
    void firewall() throws Exception {
        check("samples/ufw-firewall.log", "UFW / iptables firewall", "HIGH", "PORT_SCAN", "FIREWALL_BLOCKS");
    }

    @Test
    void kubernetes() throws Exception {
        check("samples/kubernetes.log", "Docker / Kubernetes", "CRITICAL",
                "CRASH_LOOP", "OOM_KILL", "PROBE_FAILURES", "IMAGE_PULL_ERRORS");
    }

    @Test
    void theDefaultMixedSampleStillShowsTheHeadlineDetections() throws Exception {
        LogSummary s = summarize("sample.log");
        assertTrue(s.detectedFormat().startsWith("Mixed: Apache / Nginx access"));
        assertEquals("CRITICAL", s.riskLevel());
    }
}
