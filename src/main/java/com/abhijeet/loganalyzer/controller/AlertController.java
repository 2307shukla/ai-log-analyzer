package com.abhijeet.loganalyzer.controller;

import com.abhijeet.loganalyzer.service.AlertRuleLoader;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@Tag(name = "Alerts", description = "Configured alert rules")
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertRuleLoader loader;

    public AlertController(AlertRuleLoader loader) {
        this.loader = loader;
    }

    /** The active rules, where they came from, and any rules that were skipped as invalid. */
    @Operation(summary = "List the active alert rules (from alert-rules.yml or ALERT_RULES_FILE)")
    @GetMapping("/rules")
    public Map<String, Object> rules() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("source", loader.source());
        body.put("rules", loader.rules());
        body.put("errors", loader.errors());
        return body;
    }
}
