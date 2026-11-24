package com.abhijeet.loganalyzer.model;

import java.util.List;

/** A question about the loaded log, with the recent conversation for follow-ups. */
public record ChatRequest(String question, List<ChatTurn> history) {
}
