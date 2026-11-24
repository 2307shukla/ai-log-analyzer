package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.AlertRule;

import java.util.List;

/** Supplies the active alert rules. */
public interface AlertRuleSource {

    List<AlertRule> rules();

    AlertRuleSource NONE = List::of;
}
