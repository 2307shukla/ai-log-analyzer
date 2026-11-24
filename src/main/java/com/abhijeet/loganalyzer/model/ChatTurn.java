package com.abhijeet.loganalyzer.model;

/** One earlier message in the chat: role is "user" or "assistant". */
public record ChatTurn(String role, String content) {
}
