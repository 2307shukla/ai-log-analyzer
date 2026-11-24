package com.abhijeet.loganalyzer.model;

import java.util.List;

/**
 * One detected security issue. Everything here is computed locally from the log, so a finding
 * is reproducible and can be traced back to evidence lines.
 *
 * @param rule           stable identifier of the detection rule, for example BRUTE_FORCE
 * @param title          short human readable name
 * @param severity       how serious it is
 * @param mitre          MITRE ATT&CK technique this maps to, or null when none applies
 * @param count          number of log events that matched
 * @param description    what was seen and why it matters
 * @param evidence       up to a few concrete examples taken from the log
 * @param recommendation defensive next step
 */
public record Finding(
        String rule,
        String title,
        Severity severity,
        String mitre,
        int count,
        String description,
        List<String> evidence,
        String recommendation
) {
}
