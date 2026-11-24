package com.abhijeet.loganalyzer.config;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.tags.Tag;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI logAnalyzerOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("AI Log Analyzer API")
                        .version("2.0.0")
                        .license(new License().name("MIT").url("https://opensource.org/licenses/MIT"))
                        .description("""
                                Deterministic log analysis with an LLM-written incident report.

                                Upload a log in any supported format (Apache/Nginx, SSH auth, Linux syslog,
                                JSON lines, Spring Boot/Java, Windows Security events, AWS CloudTrail,
                                UFW/iptables, Docker/Kubernetes); the format is detected per line. Detection,
                                MITRE ATT&CK tagging, risk scoring, suspicious-IP scoring with offline GeoIP and
                                alert rules all run in plain Java. The model only receives the computed summary
                                and writes the incident report or answers chat questions.

                                Uploads are private to the caller's session (a cookie). Upload, analysis and chat
                                are rate limited per client.
                                """))
                .externalDocs(new ExternalDocumentation()
                        .description("Source code and README")
                        .url("https://github.com/2307shukla/ai-log-analyzer"))
                .tags(List.of(
                        new Tag().name("Logs").description("Upload, samples, formats, summary, timeline, AI report, chat and exports"),
                        new Tag().name("Alerts").description("Configured alert rules")));
    }
}
