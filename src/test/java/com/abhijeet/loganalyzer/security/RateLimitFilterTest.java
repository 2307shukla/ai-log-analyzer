package com.abhijeet.loganalyzer.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RateLimitFilterTest {

    private final RateLimitFilter filter = new RateLimitFilter();

    private int call(String path, String forwardedFor, String remoteAddr) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr(remoteAddr);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response.getStatus();
    }

    @Test
    void analyzeIsLimitedPerClient() throws Exception {
        for (int i = 0; i < RateLimitFilter.ANALYZE_PER_CLIENT; i++) {
            assertEquals(200, call("/api/logs/analyze", null, "10.0.0.1"));
        }
        assertEquals(429, call("/api/logs/analyze", null, "10.0.0.1"));
        // A different client is unaffected.
        assertEquals(200, call("/api/logs/analyze", null, "10.0.0.2"));
    }

    @Test
    void fakingTheFirstForwardedForEntryDoesNotEvadeTheLimit() throws Exception {
        // The proxy appends the real address last; the caller controls everything before it.
        for (int i = 0; i < RateLimitFilter.ANALYZE_PER_CLIENT; i++) {
            assertEquals(200, call("/api/logs/analyze", "fake-" + i + ", 203.0.113.9", "10.9.9.9"));
        }
        assertEquals(429, call("/api/logs/analyze", "fake-new, 203.0.113.9", "10.9.9.9"));
    }

    @Test
    void globalLimitProtectsTheProviderEvenAcrossManyClients() throws Exception {
        for (int i = 0; i < RateLimitFilter.ANALYZE_GLOBAL; i++) {
            assertEquals(200, call("/api/logs/analyze", "198.51.100." + i, "10.0.0.1"));
        }
        assertEquals(429, call("/api/logs/analyze", "198.51.100.200", "10.0.0.1"));
    }

    @Test
    void uploadIsLimitedPerClient() throws Exception {
        for (int i = 0; i < RateLimitFilter.UPLOAD_PER_CLIENT; i++) {
            assertEquals(200, call("/api/logs/upload", null, "10.0.0.3"));
        }
        assertEquals(429, call("/api/logs/upload", null, "10.0.0.3"));
    }

    @Test
    void cheapEndpointsAreNotLimited() throws Exception {
        for (int i = 0; i < 100; i++) {
            assertEquals(200, call("/api/logs/summary", null, "10.0.0.4"));
        }
    }

    @Test
    void clientKeyUsesTheLastForwardedEntryAndFallsBackToTheSocketAddress() {
        assertEquals("203.0.113.9", RateLimitFilter.clientKey("fake, 203.0.113.9", "10.0.0.1"));
        assertEquals("203.0.113.9", RateLimitFilter.clientKey("203.0.113.9", "10.0.0.1"));
        assertEquals("10.0.0.1", RateLimitFilter.clientKey(null, "10.0.0.1"));
        assertEquals("10.0.0.1", RateLimitFilter.clientKey("  ", "10.0.0.1"));
    }

    @Test
    void chatSharesTheAnalyzeBudgetBecauseBothCallTheModel() throws Exception {
        for (int i = 0; i < RateLimitFilter.ANALYZE_PER_CLIENT; i++) {
            assertEquals(200, call(i % 2 == 0 ? "/api/logs/chat" : "/api/logs/analyze", null, "10.7.7.7"));
        }
        assertEquals(429, call("/api/logs/chat", null, "10.7.7.7"));
    }
}
