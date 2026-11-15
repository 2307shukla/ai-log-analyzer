package com.abhijeet.loganalyzer.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI logAnalyzerOpenApi() {
        return new OpenAPI().info(new Info()
                .title("AI Log Analyzer API")
                .version("1.0.0")
                .description("""
                        Deterministic security log analysis with an LLM-written incident report.

                        Upload an Apache/Nginx access log or an SSH auth log. Detection
                        (brute force, injection probes, scanning, 5xx clustering) runs in
                        plain Java; the model receives only the computed summary and writes
                        the narrative report.
                        """));
    }
}
