package com.abhijeet.loganalyzer.model;

import java.util.List;

/**
 * One source address and why it looks suspicious.
 *
 * @param ip             the address
 * @param score          0 to 100, from what the address did (see IpProfiler)
 * @param severity       LOW, MEDIUM, HIGH or CRITICAL, from the score
 * @param events         log entries from this address
 * @param failedLogins   failed authentications
 * @param attackRequests requests carrying injection, XSS or traversal payloads
 * @param probes         requests for sensitive paths
 * @param blocked        connections the firewall blocked
 * @param portsProbed    distinct destination ports tried
 * @param reasons        what contributed to the score, most important first
 * @param network        Public, Private network, Loopback, Documentation range, ...
 * @param country        country name from GeoIP, or null
 * @param countryCode    ISO country code from GeoIP, or null
 * @param city           city name from GeoIP, or null
 */
public record SuspiciousIp(String ip, int score, String severity, int events, int failedLogins,
                           int attackRequests, int probes, int blocked, int portsProbed,
                           List<String> reasons, String network, String country, String countryCode,
                           String city) {
}
