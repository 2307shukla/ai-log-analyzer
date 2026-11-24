package com.abhijeet.loganalyzer.model;

/** The log formats the parser recognises, detected per line. */
public enum LogFormat {
    APACHE("Apache / Nginx access"),
    SSH("SSH auth"),
    SYSLOG("Linux syslog"),
    JSON("JSON lines"),
    SPRING_BOOT("Spring Boot / Java"),
    WINDOWS_EVENT("Windows Security Event"),
    CLOUDTRAIL("AWS CloudTrail"),
    FIREWALL("UFW / iptables firewall"),
    CONTAINER("Docker / Kubernetes"),
    UNKNOWN("Unrecognised");

    private final String label;

    LogFormat(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
