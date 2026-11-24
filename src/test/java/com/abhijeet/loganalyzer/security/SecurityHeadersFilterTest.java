package com.abhijeet.loganalyzer.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SecurityHeadersFilterTest {

    private final SecurityHeadersFilter filter = new SecurityHeadersFilter();

    private MockHttpServletResponse call(String path, boolean secure) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setSecure(secure);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    @Test
    void addsBrowserHardeningHeaders() throws Exception {
        MockHttpServletResponse response = call("/", false);

        assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
        assertEquals("DENY", response.getHeader("X-Frame-Options"));
        assertEquals("no-referrer", response.getHeader("Referrer-Policy"));
        assertEquals(SecurityHeadersFilter.CSP, response.getHeader("Content-Security-Policy"));
        assertNull(response.getHeader("Strict-Transport-Security"));
    }

    @Test
    void sendsHstsOnlyOverHttps() throws Exception {
        assertEquals("max-age=31536000", call("/", true).getHeader("Strict-Transport-Security"));
    }

    @Test
    void leavesSwaggerUiWithoutTheContentSecurityPolicy() throws Exception {
        assertNull(call("/swagger-ui/index.html", false).getHeader("Content-Security-Policy"));
        assertEquals("DENY", call("/swagger-ui/index.html", false).getHeader("X-Frame-Options"));
    }
}
