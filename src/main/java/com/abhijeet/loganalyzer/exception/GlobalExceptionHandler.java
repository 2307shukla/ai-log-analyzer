package com.abhijeet.loganalyzer.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns failures into readable JSON instead of Spring's Whitelabel error page.
 *
 * Without this, every provider error - bad key, exhausted quota, wrong model -
 * looks identical: a blank 500.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> missingParameter(MissingServletRequestParameterException ex) {
        return ResponseEntity.badRequest()
                .body(body("Missing parameter: " + ex.getParameterName(), null));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, Object>> tooLarge(MaxUploadSizeExceededException ex) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(body("File too large. Maximum upload size is 10MB.", null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAny(Exception ex) {
        log.error("Request failed", ex);

        String message = ex.getMessage();
        String type = ex.getClass().getSimpleName();
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        if (message != null) {
            String m = message.toLowerCase();
            if (m.contains("401") || m.contains("unauthorized") || m.contains("invalid api key")) {
                status = HttpStatus.UNAUTHORIZED;
            } else if (m.contains("402") || m.contains("insufficient") || m.contains("quota")
                    || m.contains("429") || m.contains("rate limit")) {
                status = HttpStatus.TOO_MANY_REQUESTS;
            } else if (m.contains("404") || m.contains("model_not_found") || m.contains("not found")) {
                status = HttpStatus.BAD_GATEWAY;
            }
        }

        return ResponseEntity.status(status).body(body(type, message));
    }

    private Map<String, Object> body(String error, String detail) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("error", error);
        if (detail != null && !detail.isBlank()) {
            payload.put("detail", detail);
        }
        return payload;
    }
}
