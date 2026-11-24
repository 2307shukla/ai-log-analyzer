package com.abhijeet.loganalyzer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Paths;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Phase 2 endpoints, with the small fake GeoIP database from src/test/resources. */
@SpringBootTest
@AutoConfigureMockMvc
class AnalysisIntegrationTest {

    @DynamicPropertySource
    static void geoip(DynamicPropertyRegistry registry) {
        registry.add("geoip.database", () -> {
            try {
                return Paths.get(AnalysisIntegrationTest.class.getResource("/geoip/test-city.mmdb").toURI()).toString();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    @Autowired
    private MockMvc mockMvc;

    private static org.springframework.test.web.servlet.request.RequestPostProcessor client(String addr) {
        return request -> {
            request.setRemoteAddr(addr);
            return request;
        };
    }

    @Test
    void timelineEndpointOffersMinuteAndHourViews() throws Exception {
        mockMvc.perform(get("/api/logs/timeline").param("bucket", "minute"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bucketMinutes").value(1))
                .andExpect(jsonPath("$.points[0].authFailures").exists())
                .andExpect(jsonPath("$.points[0].spike").exists());
        mockMvc.perform(get("/api/logs/timeline").param("bucket", "hour"))
                .andExpect(jsonPath("$.bucketMinutes").value(60))
                .andExpect(jsonPath("$.points", hasSize(13)));
        mockMvc.perform(get("/api/logs/timeline").param("bucket", "week"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void theDefaultSampleTriggersTheExampleAlert() throws Exception {
        mockMvc.perform(get("/api/logs/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.alerts[*].ruleId", hasItem("brute-force-burst")))
                .andExpect(jsonPath("$.summary.alerts[*].ruleId", hasItem("compromised-account")))
                .andExpect(jsonPath("$.summary.alerts[0].severity").value("CRITICAL"))
                .andExpect(jsonPath("$.summary.suspiciousIps[0].ip").value("203.0.113.5"))
                .andExpect(jsonPath("$.summary.suspiciousIps[0].network").value("Documentation range"))
                .andExpect(jsonPath("$.summary.geoipSource").value("DBIP-City-Lite"));
    }

    @Test
    void rulesEndpointListsTheBundledRules() throws Exception {
        mockMvc.perform(get("/api/alerts/rules"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rules", hasSize(20)))
                .andExpect(jsonPath("$.errors", hasSize(0)))
                .andExpect(jsonPath("$.source", containsString("bundled")));
    }

    @Test
    void publicAttackersAreLocatedWithTheOfflineDatabase() throws Exception {
        StringBuilder log = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            log.append("Nov 12 03:20:").append(10 + i).append(" web01 sshd[1]: Failed password for root from 8.8.8.8 port 22 ssh2\n");
        }
        MockMultipartFile file = new MockMultipartFile("file", "auth.log", "text/plain", log.toString().getBytes());

        mockMvc.perform(multipart("/api/logs/upload").file(file).session(new MockHttpSession()).with(client("10.88.0.1")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.suspiciousIps[0].ip").value("8.8.8.8"))
                .andExpect(jsonPath("$.summary.suspiciousIps[0].country").value("Testland"))
                .andExpect(jsonPath("$.summary.suspiciousIps[0].city").value("Test City"))
                .andExpect(jsonPath("$.summary.suspiciousIps[0].score", greaterThan(0)))
                .andExpect(jsonPath("$.summary.alerts[0].ruleId").value("brute-force-burst"));
    }

    @Test
    void everySampleProducesAlertsOrIsExplicitlyQuiet() throws Exception {
        String[] noisy = {"ssh", "windows", "cloudtrail", "firewall", "spring", "kubernetes", "syslog"};
        for (String id : noisy) {
            MockHttpSession session = new MockHttpSession();
            mockMvc.perform(post("/api/logs/samples/" + id).session(session).with(client("10.88.1." + id.length())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.summary.alerts", hasSize(greaterThan(0))));
        }
    }

    @Test
    void theChartLibraryIsServedLocally() throws Exception {
        mockMvc.perform(get("/vendor/chart.umd.min.js"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Chart.js v4")));
    }
}
