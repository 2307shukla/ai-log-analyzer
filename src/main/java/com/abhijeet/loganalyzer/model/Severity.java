package com.abhijeet.loganalyzer.model;

/** How serious a finding is. The weight feeds the overall risk score. */
public enum Severity {
    CRITICAL(40),
    HIGH(25),
    MEDIUM(12),
    LOW(4);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }
}
