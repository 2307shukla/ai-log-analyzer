package com.abhijeet.loganalyzer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Validation runs before any AI call, so these tests never reach the provider. */
@SpringBootTest
@AutoConfigureMockMvc
class ChatEndpointIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void rejectsAnEmptyQuestion() throws Exception {
        mockMvc.perform(post("/api/logs/chat").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"question\":\"   \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Type a question first."));
    }

    @Test
    void rejectsAQuestionThatIsTooLong() throws Exception {
        mockMvc.perform(post("/api/logs/chat").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"question\":\"" + "a".repeat(501) + "\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsABodyThatIsNotJson() throws Exception {
        mockMvc.perform(post("/api/logs/chat").contentType(MediaType.APPLICATION_JSON).content("not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Request body must be JSON."));
    }
}
