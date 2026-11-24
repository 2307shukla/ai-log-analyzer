package com.abhijeet.loganalyzer.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void doesNotLeakProviderErrorTextToTheClient() {
        String secret = "key=AIza-secret-123 at https://internal.example/v1beta";
        ResponseEntity<Map<String, Object>> response =
                handler.handleAny(new RuntimeException("401 Unauthorized " + secret));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertFalse(String.valueOf(response.getBody()).contains("AIza-secret-123"));
        assertFalse(String.valueOf(response.getBody()).contains("internal.example"));
        assertNull(response.getBody().get("detail"));
    }

    @Test
    void mapsQuotaErrorsToTooManyRequests() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleAny(new RuntimeException("429 quota exceeded"));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
    }

    @Test
    void unknownFailuresAreAGenericServerError() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleAny(new IllegalStateException("db password is hunter2"));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertFalse(String.valueOf(response.getBody()).contains("hunter2"));
    }
}
