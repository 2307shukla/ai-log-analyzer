package com.abhijeet.loganalyzer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SessionIsolationIntegrationTest {

    private static final String LINE = "203.0.113.45 - - [12/Nov/2026:08:09:03 +0000] "
            + "\"GET /private HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void anUploadIsOnlyVisibleToTheSessionThatMadeIt() throws Exception {
        MockHttpSession alice = new MockHttpSession();
        MockMultipartFile file = new MockMultipartFile(
                "file", "alice-private.log", "text/plain", LINE.getBytes());

        mockMvc.perform(multipart("/api/logs/upload").file(file).session(alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.file").value("alice-private.log"));

        mockMvc.perform(get("/api/logs/summary").session(alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.file").value("alice-private.log"));

        // Another visitor must see the bundled sample, never Alice's file.
        mockMvc.perform(get("/api/logs/summary").session(new MockHttpSession()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.file").value("sample.log"));

        // A visitor with no session at all sees the sample too.
        mockMvc.perform(get("/api/logs/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.file").value("sample.log"));
    }

    @Test
    void healthEndpointIsPublicAndResponsesCarrySecurityHeaders() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }
}
