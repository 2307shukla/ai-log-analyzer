package com.abhijeet.loganalyzer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class FormatsAndSamplesIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private static final java.util.concurrent.atomic.AtomicInteger CLIENT = new java.util.concurrent.atomic.AtomicInteger();

    /** A new client address per request, so this test never trips the per-client upload limit. */
    private static org.springframework.test.web.servlet.request.RequestPostProcessor client() {
        int n = CLIENT.incrementAndGet();
        return request -> {
            request.setRemoteAddr("10.77." + (n / 250) + "." + (n % 250));
            return request;
        };
    }

    @Test
    void listsOneSamplePerFormat() throws Exception {
        mockMvc.perform(get("/api/logs/samples"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(10)))
                .andExpect(jsonPath("$[*].id", hasItem("cloudtrail")));
    }

    @Test
    void loadingEverySampleDetectsItsFormat() throws Exception {
        String[][] expected = {
                {"apache", "Apache / Nginx access"}, {"ssh", "SSH auth"}, {"syslog", "Linux syslog"},
                {"json", "JSON lines"}, {"spring", "Spring Boot / Java"}, {"windows", "Windows Security Event"},
                {"cloudtrail", "AWS CloudTrail"}, {"firewall", "UFW / iptables firewall"},
                {"kubernetes", "Docker / Kubernetes"}};
        for (String[] sample : expected) {
            MockHttpSession session = new MockHttpSession();
            mockMvc.perform(post("/api/logs/samples/" + sample[0]).session(session).with(client()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.summary.detectedFormat").value(sample[1]));
            // The loaded sample is now this visitor's log.
            mockMvc.perform(get("/api/logs/summary").session(session))
                    .andExpect(jsonPath("$.summary.detectedFormat").value(sample[1]));
        }
    }

    @Test
    void unknownSampleIs404() throws Exception {
        mockMvc.perform(post("/api/logs/samples/nope").with(client())).andExpect(status().isNotFound());
    }

    @Test
    void listsFormatsForTheOverride() throws Exception {
        mockMvc.perform(get("/api/logs/formats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value("auto"))
                .andExpect(jsonPath("$[*].id", hasItem("windows_event")))
                .andExpect(jsonPath("$[*].id", hasItem("syslog")));
    }

    @Test
    void overrideReparsesOnlyTheCallersLog() throws Exception {
        MockHttpSession session = new MockHttpSession();
        mockMvc.perform(post("/api/logs/samples/ssh").session(session).with(client())).andExpect(status().isOk());

        mockMvc.perform(post("/api/logs/format").param("format", "apache").session(session).with(client()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").value("apache"))
                .andExpect(jsonPath("$.summary.detectedFormat").value("Unrecognised"));

        mockMvc.perform(post("/api/logs/format").param("format", "auto").session(session).with(client()))
                .andExpect(jsonPath("$.summary.detectedFormat").value("SSH auth"));

        // A visitor without an upload still sees the untouched default sample.
        mockMvc.perform(get("/api/logs/summary"))
                .andExpect(jsonPath("$.file").value("sample.log"));
    }

    @Test
    void rejectsAnUnknownFormat() throws Exception {
        mockMvc.perform(post("/api/logs/format").param("format", "word").with(client()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", containsString("Unknown format")));
        MockMultipartFile file = new MockMultipartFile("file", "a.log", "text/plain", "x 1.2.3.4".getBytes());
        mockMvc.perform(multipart("/api/logs/upload").file(file).param("format", "word").with(client()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void uploadWithAForcedFormat() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "fw.log", "text/plain",
                "kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.150 DST=192.0.2.20 PROTO=TCP DPT=22".getBytes());
        mockMvc.perform(multipart("/api/logs/upload").file(file).param("format", "firewall").with(client()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.detectedFormat").value("UFW / iptables firewall"))
                .andExpect(jsonPath("$.sampled").value(false));
    }

    @Test
    void largeUploadsAreSampledNotRejected() throws Exception {
        StringBuilder log = new StringBuilder();
        for (int i = 0; i < 100_050; i++) {
            log.append("192.0.2.").append(i % 200).append(" - - [12/Nov/2026:08:00:00 +0000] \"GET / HTTP/1.1\" 200 5\n");
        }
        MockMultipartFile file = new MockMultipartFile("file", "big.log", "text/plain",
                log.toString().getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/logs/upload").file(file).session(new MockHttpSession()).with(client()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sampled").value(true))
                .andExpect(jsonPath("$.loaded").value(100_000))
                .andExpect(jsonPath("$.totalLines").value(100_050));
    }
}
