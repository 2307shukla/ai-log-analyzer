package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.ChatTurn;
import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.model.LogSummary;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChatPromptTest {

    private final LogAnalysisService service = new LogAnalysisService(null);
    private final LogSummary summary = service.summarize(List.of(
            new LogEvent("203.0.113.5", "GET", "/login", 401, "sqlmap/1.7", false, "raw")));

    @Test
    void groundsTheAnswerInTheSummaryAndCarriesTheQuestion() {
        String prompt = service.chatPrompt(summary, "Which IP should I block?", List.of());

        assertTrue(prompt.contains("Question: Which IP should I block?"));
        assertTrue(prompt.contains("203.0.113.5"));
        assertTrue(prompt.contains("Answer ONLY from the log summary"));
        assertTrue(prompt.contains("(none)"));
    }

    @Test
    void keepsOnlyTheRecentConversation() {
        List<ChatTurn> history = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            history.add(new ChatTurn(i % 2 == 0 ? "user" : "assistant", "turn-" + i));
        }

        String prompt = service.chatPrompt(summary, "and then?", history);

        assertFalse(prompt.contains("turn-3"));
        assertTrue(prompt.contains("User: turn-4"));
        assertTrue(prompt.contains("Analyst: turn-9"));
    }

    @Test
    void clipsLongTextAndSkipsEmptyTurns() {
        List<ChatTurn> history = new ArrayList<>();
        history.add(null);
        history.add(new ChatTurn("user", "  "));
        history.add(new ChatTurn("assistant", "y".repeat(5000)));

        String prompt = service.chatPrompt(summary, "x".repeat(900), history);

        assertFalse(prompt.contains("x".repeat(501)));
        assertFalse(prompt.contains("y".repeat(1501)));
        assertFalse(prompt.contains("User:  "));
    }
}
