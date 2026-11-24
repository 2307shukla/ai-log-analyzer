package com.abhijeet.loganalyzer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItems;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class FeatureIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void theBundledSampleShowsTheHeadlineDetections() throws Exception {
        mockMvc.perform(get("/api/logs/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.riskLevel").value("CRITICAL"))
                .andExpect(jsonPath("$.summary.riskScore").value(greaterThan(0)))
                .andExpect(jsonPath("$.summary.findings[*].rule")
                        .value(hasItems("BRUTE_FORCE", "PASSWORD_SPRAYING", "COMPROMISED_LOGIN")))
                .andExpect(jsonPath("$.summary.timeline").isNotEmpty())
                .andExpect(jsonPath("$.summary.timelineBucketMinutes").value(greaterThan(0)));
    }

    @Test
    void exportsMarkdownAsADownload() throws Exception {
        mockMvc.perform(get("/api/logs/export").param("format", "md"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("log-analysis-report.md")))
                .andExpect(content().contentTypeCompatibleWith("text/markdown"))
                .andExpect(content().string(containsString("# Log analysis report")))
                .andExpect(content().string(containsString("Brute-force login attempts")));
    }

    @Test
    void exportsJsonAsADownload() throws Exception {
        mockMvc.perform(get("/api/logs/export").param("format", "json"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("log-analysis-report.json")))
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.summary.riskLevel").value("CRITICAL"));
    }

    @Test
    void rejectsAnUnknownExportFormat() throws Exception {
        mockMvc.perform(get("/api/logs/export").param("format", "docx"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void anExportIsBuiltFromTheCallersOwnUpload() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockMultipartFile benign = new MockMultipartFile("file", "mine.log", "text/plain",
                "198.51.100.1 - - [12/Nov/2026:08:00:00 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"Mozilla/5.0\""
                        .getBytes());

        mockMvc.perform(multipart("/api/logs/upload").file(benign).session(session))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/logs/export").param("format", "md").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("mine.log")))
                .andExpect(content().string(containsString("No findings. Traffic looks clean.")));

        // Someone else still gets the sample, not this upload.
        mockMvc.perform(get("/api/logs/export").param("format", "md"))
                .andExpect(content().string(containsString("sample.log")));
    }
}
