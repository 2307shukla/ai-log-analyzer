package com.abhijeet.loganalyzer.service;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MitreMappingTest {

    private static final Pattern TECHNIQUE = Pattern.compile("^T\\d{4}(\\.\\d{3})? [A-Z].+$");

    @Test
    void everyEntryIsAWellFormedTechnique() {
        Map<String, String> all = MitreMapping.all();
        assertTrue(all.size() >= 25);
        all.forEach((rule, technique) ->
                assertTrue(TECHNIQUE.matcher(technique).matches(), rule + " -> " + technique));
    }

    @Test
    void knownMappings() {
        assertEquals("T1110 Brute Force", MitreMapping.technique("BRUTE_FORCE"));
        assertEquals("T1046 Network Service Discovery", MitreMapping.technique("PORT_SCAN"));
        assertEquals("T1078.004 Valid Accounts: Cloud Accounts", MitreMapping.technique("ROOT_ACCOUNT_USAGE"));
    }

    @Test
    void availabilityRulesHaveNoTechnique() {
        assertNull(MitreMapping.technique("SERVER_ERRORS"));
        assertNull(MitreMapping.technique("CRASH_LOOP"));
        assertNull(MitreMapping.technique("NOT_A_RULE"));
    }
}
