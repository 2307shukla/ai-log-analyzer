package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.AlertRule;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Loads alert rules once at start-up: from the YAML or JSON file named by ALERT_RULES_FILE when
 * set, otherwise from the bundled alert-rules.yml. Invalid rules are skipped and reported (log and
 * GET /api/alerts/rules); a broken file never stops the application.
 */
@Service
public class AlertRuleLoader implements AlertRuleSource {

    private static final Logger log = LoggerFactory.getLogger(AlertRuleLoader.class);
    static final String BUNDLED = "alert-rules.yml";
    static final int MAX_RULES = 100;

    private final List<AlertRule> rules;
    private final List<String> errors;
    private final String source;

    public AlertRuleLoader(@Value("${alerts.rules-file:}") String file) {
        List<String> problems = new ArrayList<>();
        String text = null;
        String from = BUNDLED + " (bundled)";
        if (file != null && !file.isBlank()) {
            Path path = Path.of(file);
            try {
                text = Files.readString(path, StandardCharsets.UTF_8);
                from = path.getFileName().toString();
            } catch (Exception e) {
                problems.add("Could not read " + file + "; using the bundled rules instead");
            }
        }
        if (text == null) {
            try (InputStream in = new ClassPathResource(BUNDLED).getInputStream()) {
                text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            } catch (Exception e) {
                problems.add("Bundled alert rules are missing");
                text = "rules: []";
            }
        }
        this.rules = parse(text, from.toLowerCase().endsWith(".json"), problems);
        this.errors = List.copyOf(problems);
        this.source = from;
        problems.forEach(p -> log.warn("Alert rules: {}", p));
        log.info("Loaded {} alert rules from {}", rules.size(), from);
    }

    /** Parses a rules document; problems are added to {@code errors} and the bad rules skipped. */
    static List<AlertRule> parse(String text, boolean json, List<String> errors) {
        Object root;
        try {
            root = json ? new ObjectMapper().readValue(text, Object.class)
                    : new Yaml(new SafeConstructor(new LoaderOptions())).load(text);
        } catch (Exception e) {
            errors.add("The rules file is not valid " + (json ? "JSON" : "YAML") + ": " + firstLine(e.getMessage()));
            return List.of();
        }
        Object list = root instanceof Map<?, ?> map ? map.get("rules") : root;
        if (!(list instanceof List<?> items)) {
            errors.add("The rules file must contain a list named rules");
            return List.of();
        }
        List<AlertRule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < items.size() && rules.size() < MAX_RULES; i++) {
            if (!(items.get(i) instanceof Map<?, ?> item)) {
                errors.add("rule #" + (i + 1) + ": must be an object");
                continue;
            }
            AlertRule rule = AlertRule.fromMap(item, i, errors);
            if (rule == null) {
                continue;
            }
            if (!ids.add(rule.id())) {
                errors.add("rule '" + rule.id() + "': duplicate id, skipped");
                continue;
            }
            rules.add(rule);
        }
        return List.copyOf(rules);
    }

    private static String firstLine(String message) {
        return message == null ? "" : message.lines().findFirst().orElse("");
    }

    @Override
    public List<AlertRule> rules() {
        return rules;
    }

    public List<String> errors() {
        return errors;
    }

    public String source() {
        return source;
    }
}
