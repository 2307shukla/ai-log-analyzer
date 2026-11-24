package com.abhijeet.loganalyzer.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Static, local mapping from detection rule to MITRE ATT&amp;CK technique. Kept in one place so the
 * mapping can be reviewed and tested as a table. Rules about availability or hygiene (server errors,
 * crash loops) have no ATT&amp;CK technique and map to null.
 */
public final class MitreMapping {

    private static final Map<String, String> TECHNIQUES = new LinkedHashMap<>();

    static {
        // Credential access
        put("BRUTE_FORCE", "T1110 Brute Force");
        put("WEB_LOGIN_BRUTE_FORCE", "T1110.001 Brute Force: Password Guessing");
        put("PASSWORD_SPRAYING", "T1110.003 Brute Force: Password Spraying");
        put("ACCOUNT_LOCKOUT", "T1110 Brute Force");
        // Initial access / valid accounts
        put("COMPROMISED_LOGIN", "T1078 Valid Accounts");
        put("SSH_ROOT_LOGIN", "T1078.003 Valid Accounts: Local Accounts");
        put("PRIVILEGE_USE", "T1078.002 Valid Accounts: Domain Accounts");
        put("ROOT_ACCOUNT_USAGE", "T1078.004 Valid Accounts: Cloud Accounts");
        put("CONSOLE_LOGIN_WITHOUT_MFA", "T1078.004 Valid Accounts: Cloud Accounts");
        put("SQL_INJECTION", "T1190 Exploit Public-Facing Application");
        put("XSS", "T1190 Exploit Public-Facing Application");
        put("PATH_TRAVERSAL", "T1190 Exploit Public-Facing Application");
        // Reconnaissance and discovery
        put("SENSITIVE_PATH_PROBING", "T1595.003 Active Scanning: Wordlist Scanning");
        put("FORCED_BROWSING", "T1595.003 Active Scanning: Wordlist Scanning");
        put("SCANNER_USER_AGENT", "T1595.002 Active Scanning: Vulnerability Scanning");
        put("PORT_SCAN", "T1046 Network Service Discovery");
        // Persistence and privilege escalation
        put("ACCOUNT_CREATED", "T1136.001 Create Account: Local Account");
        put("PRIVILEGED_GROUP_CHANGE", "T1098 Account Manipulation");
        put("IAM_CHANGES", "T1098 Account Manipulation");
        put("SUDO_SU_USAGE", "T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching");
        put("SUDO_SU_FAILURES", "T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching");
        // Defense evasion and impact
        put("AUDIT_LOG_CLEARED", "T1070.001 Indicator Removal: Clear Windows Event Logs");
        put("CLOUD_LOGGING_DISABLED", "T1562.008 Impair Defenses: Disable or Modify Cloud Logs");
        put("DELETED_RESOURCES", "T1485 Data Destruction");
        put("REQUEST_BURST", "T1498 Network Denial of Service");
    }

    private MitreMapping() {
    }

    private static void put(String rule, String technique) {
        TECHNIQUES.put(rule, technique);
    }

    /** The technique for a rule, or null when the rule has none. */
    public static String technique(String rule) {
        return TECHNIQUES.get(rule);
    }

    public static Map<String, String> all() {
        return Collections.unmodifiableMap(TECHNIQUES);
    }
}
