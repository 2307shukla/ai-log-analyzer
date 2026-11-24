package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.AlertRule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertRuleLoaderTest {

    @Test
    void theBundledRulesAllLoadWithoutErrors() {
        AlertRuleLoader loader = new AlertRuleLoader("");
        assertTrue(loader.errors().isEmpty(), loader.errors().toString());
        assertEquals(20, loader.rules().size());
        AlertRule burst = loader.rules().get(0);
        assertEquals("brute-force-burst", burst.id());
        assertEquals("failed_logins", burst.metric());
        assertEquals(5, burst.threshold());
        assertEquals(1, burst.windowMinutes());
        assertTrue(loader.source().contains("bundled"));
    }

    @Test
    void readsACustomYamlFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("my-rules.yml");
        Files.writeString(file, """
                rules:
                  - id: ten-404s
                    name: Ten missing pages
                    metric: not_found
                    groupBy: ip
                    threshold: 10
                    windowMinutes: 2
                    severity: low
                  - id: broken
                    metric: nope
                """);
        AlertRuleLoader loader = new AlertRuleLoader(file.toString());
        assertEquals(1, loader.rules().size());
        assertEquals("my-rules.yml", loader.source());
        assertTrue(loader.errors().stream().anyMatch(e -> e.startsWith("rule 'broken'")));
    }

    @Test
    void readsJsonAndRejectsDuplicates() {
        List<String> errors = new ArrayList<>();
        List<AlertRule> rules = AlertRuleLoader.parse("""
                [{"id":"a","name":"A","metric":"events","threshold":1},
                 {"id":"a","name":"A again","metric":"events","threshold":2}]
                """, true, errors);
        assertEquals(1, rules.size());
        assertTrue(errors.get(0).contains("duplicate"));
    }

    @Test
    void aBrokenOrMissingFileNeverStopsTheApp(@TempDir Path dir) throws Exception {
        List<String> errors = new ArrayList<>();
        assertTrue(AlertRuleLoader.parse("rules: [unclosed", false, errors).isEmpty());
        assertTrue(errors.get(0).startsWith("The rules file is not valid YAML"));

        AlertRuleLoader missing = new AlertRuleLoader(dir.resolve("nope.yml").toString());
        assertEquals(20, missing.rules().size(), "falls back to the bundled rules");
        assertTrue(missing.errors().get(0).startsWith("Could not read"));
    }

    @Test
    void yamlTagsCannotConstructJavaObjects() {
        List<String> errors = new ArrayList<>();
        AlertRuleLoader.parse("rules: !!java.io.File [\"/etc/passwd\"]", false, errors);
        assertTrue(errors.get(0).startsWith("The rules file is not valid YAML"));
    }
}
