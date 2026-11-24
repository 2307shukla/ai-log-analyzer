package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.AlertRule;
import com.abhijeet.loganalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertRuleTest {

    private static Map<String, Object> valid() {
        Map<String, Object> m = new HashMap<>();
        m.put("id", "brute-force-burst");
        m.put("name", "More than 5 failed logins from one IP in 1 minute");
        m.put("metric", "failed_logins");
        m.put("groupBy", "ip");
        m.put("threshold", 5);
        m.put("windowMinutes", 1);
        m.put("severity", "high");
        return m;
    }

    @Test
    void readsAValidRuleWithDefaults() {
        List<String> errors = new ArrayList<>();
        AlertRule rule = AlertRule.fromMap(valid(), 0, errors);
        assertTrue(errors.isEmpty(), errors.toString());
        assertEquals(Severity.HIGH, rule.severity());
        assertEquals("gt", rule.operator());

        Map<String, Object> minimal = valid();
        minimal.remove("groupBy");
        minimal.remove("severity");
        minimal.remove("windowMinutes");
        AlertRule defaults = AlertRule.fromMap(minimal, 0, errors);
        assertEquals("global", defaults.groupBy());
        assertEquals(Severity.MEDIUM, defaults.severity());
        assertEquals(0, defaults.windowMinutes());
    }

    @Test
    void reportsEveryProblemWithTheRuleName() {
        Map<String, Object> bad = valid();
        bad.put("metric", "bitcoins");
        bad.put("threshold", "lots");
        bad.put("severity", "urgent");
        bad.put("groupBy", "country");
        List<String> errors = new ArrayList<>();

        assertNull(AlertRule.fromMap(bad, 0, errors));
        assertEquals(4, errors.size());
        assertTrue(errors.stream().allMatch(e -> e.startsWith("rule 'brute-force-burst': ")));
    }

    @Test
    void findingRulesNeedARuleId() {
        Map<String, Object> m = valid();
        m.put("metric", "finding");
        List<String> errors = new ArrayList<>();
        assertNull(AlertRule.fromMap(m, 0, errors));
        assertTrue(errors.get(0).contains("needs rule"));
    }

    @Test
    void disabledRulesAreSkippedQuietly() {
        Map<String, Object> m = valid();
        m.put("enabled", false);
        List<String> errors = new ArrayList<>();
        assertNull(AlertRule.fromMap(m, 0, errors));
        assertTrue(errors.isEmpty());
    }
}
