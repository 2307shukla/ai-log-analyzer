package com.abhijeet.loganalyzer.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpClassifierTest {

    @Test
    void classifiesNetworks() {
        assertEquals("Public", IpClassifier.classify("8.8.8.8"));
        assertEquals("Private network", IpClassifier.classify("10.1.2.3"));
        assertEquals("Private network", IpClassifier.classify("172.20.0.1"));
        assertEquals("Public", IpClassifier.classify("172.32.0.1"));
        assertEquals("Private network", IpClassifier.classify("192.168.1.31"));
        assertEquals("Loopback", IpClassifier.classify("127.0.0.1"));
        assertEquals("Link-local", IpClassifier.classify("169.254.10.1"));
        assertEquals("Carrier-grade NAT", IpClassifier.classify("100.64.0.1"));
        assertEquals("Documentation range", IpClassifier.classify("203.0.113.5"));
        assertEquals("Documentation range", IpClassifier.classify("198.51.100.7"));
        assertEquals("Documentation range", IpClassifier.classify("192.0.2.10"));
        assertEquals("Reserved", IpClassifier.classify("240.0.0.1"));
        assertEquals("Loopback", IpClassifier.classify("::1"));
        assertEquals("Private network", IpClassifier.classify("fd00::1"));
        assertEquals("Documentation range", IpClassifier.classify("2001:db8::1"));
        assertEquals("Public", IpClassifier.classify("2606:4700::1111"));
    }

    @Test
    void onlyLiteralAddressesAreAccepted() {
        assertTrue(IpClassifier.isLiteral("8.8.8.8"));
        assertTrue(IpClassifier.isLiteral("2001:db8::1"));
        assertFalse(IpClassifier.isLiteral("example.com"));
        assertFalse(IpClassifier.isLiteral("999.1.1.1"));
        assertFalse(IpClassifier.isLiteral(null));
        assertEquals("Not an address", IpClassifier.classify("cloudtrail.amazonaws.com"));
    }
}
