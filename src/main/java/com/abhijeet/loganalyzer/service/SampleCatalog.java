package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Bundled example logs, one per supported format, parsed once at start-up so visitors can try
 * every format without having a log of their own. All addresses use documentation ranges.
 */
@Service
public class SampleCatalog {

    private static final Logger log = LoggerFactory.getLogger(SampleCatalog.class);

    public record Sample(String id, String name, String file, List<LogEvent> events) {
    }

    /** Public listing entry, without the events. */
    public record Info(String id, String name, String file) {
    }

    /** id, display name, classpath location. */
    private static final String[][] SAMPLES = {
            {"web", "Mixed: web attack + SSH (default)", "sample.log"},
            {"apache", "Apache / Nginx access", "samples/apache-access.log"},
            {"ssh", "SSH auth", "samples/ssh-auth.log"},
            {"syslog", "Linux syslog (sudo, su, useradd)", "samples/linux-syslog.log"},
            {"json", "JSON lines", "samples/json-lines.jsonl"},
            {"spring", "Spring Boot / Java", "samples/spring-boot.log"},
            {"windows", "Windows Security events", "samples/windows-security.log"},
            {"cloudtrail", "AWS CloudTrail", "samples/cloudtrail.json"},
            {"firewall", "UFW / iptables firewall", "samples/ufw-firewall.log"},
            {"kubernetes", "Docker / Kubernetes", "samples/kubernetes.log"},
    };

    private final Map<String, Sample> samples = new LinkedHashMap<>();

    public SampleCatalog(LogParser parser) {
        for (String[] s : SAMPLES) {
            ClassPathResource resource = new ClassPathResource(s[2]);
            if (!resource.exists()) {
                log.warn("Sample {} is missing", s[2]);
                continue;
            }
            try (InputStream in = resource.getInputStream()) {
                List<LogEvent> events = parser.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                samples.put(s[0], new Sample(s[0], s[1], s[2].substring(s[2].lastIndexOf('/') + 1), List.copyOf(events)));
            } catch (Exception e) {
                log.warn("Could not load sample {}: {}", s[2], e.getMessage());
            }
        }
    }

    public List<Info> list() {
        List<Info> infos = new ArrayList<>();
        samples.values().forEach(s -> infos.add(new Info(s.id(), s.name(), s.file())));
        return infos;
    }

    public Optional<Sample> get(String id) {
        return Optional.ofNullable(samples.get(id));
    }
}
