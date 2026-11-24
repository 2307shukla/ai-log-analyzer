package com.abhijeet.loganalyzer.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Token-bucket rate limiting on the endpoints that are expensive.
 *
 * <ul>
 *   <li>{@code /api/logs/analyze} calls the AI provider. Without a limit, a script could
 *       burn the whole free Gemini quota in minutes and take the demo down. It has a
 *       per-client limit and a global limit across all clients.</li>
 *   <li>{@code /api/logs/upload} parses up to 10MB into memory, so it has a per-client limit.</li>
 * </ul>
 *
 * The global limit is the one that guarantees the provider quota is safe, even if a caller
 * manages to look like many different clients. Buckets are in memory, so this protects one
 * instance; a multi-instance deployment would move them to Redis.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    static final int ANALYZE_PER_CLIENT = 10;
    static final int ANALYZE_GLOBAL = 60;
    static final int UPLOAD_PER_CLIENT = 20;
    private static final Duration REFILL = Duration.ofMinutes(1);
    private static final int MAX_CLIENTS = 10_000;

    private final Map<String, Bucket> analyzeBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> uploadBuckets = new ConcurrentHashMap<>();
    private final Bucket analyzeGlobal = newBucket(ANALYZE_GLOBAL);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String uri = request.getRequestURI();
        String client = clientKey(request.getHeader("X-Forwarded-For"), request.getRemoteAddr());

        boolean allowed = true;
        if ("/api/logs/analyze".equals(uri) || "/api/logs/chat".equals(uri)) {
            allowed = take(analyzeBuckets, ANALYZE_PER_CLIENT, client) && analyzeGlobal.tryConsume(1);
        } else if ("/api/logs/upload".equals(uri)) {
            allowed = take(uploadBuckets, UPLOAD_PER_CLIENT, client);
        }

        if (allowed) {
            chain.doFilter(request, response);
            return;
        }

        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write(
                "{\"error\":\"Too many requests. Please wait a minute and try again.\"}");
    }

    private boolean take(Map<String, Bucket> buckets, int capacity, String client) {
        if (buckets.size() > MAX_CLIENTS) {
            buckets.clear();
        }
        return buckets.computeIfAbsent(client, key -> newBucket(capacity)).tryConsume(1);
    }

    /**
     * The address used to tell clients apart.
     *
     * A client can send its own X-Forwarded-For header, and Render appends the real address
     * to the end instead of replacing the header. The first entry is therefore attacker
     * controlled, while the last one was added by the proxy and cannot be forged.
     */
    static String clientKey(String forwardedFor, String remoteAddr) {
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            String[] parts = forwardedFor.split(",");
            String last = parts[parts.length - 1].trim();
            if (!last.isEmpty()) {
                return last;
            }
        }
        return remoteAddr;
    }

    private static Bucket newBucket(int capacity) {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(capacity)
                        .refillGreedy(capacity, REFILL)
                        .build())
                .build();
    }
}
