package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.GeoLocation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Uses a tiny generated database with fake data (scripts/make-test-geoip-db.py). */
class GeoIpServiceTest {

    static String testDatabase() throws Exception {
        return Paths.get(GeoIpServiceTest.class.getResource("/geoip/test-city.mmdb").toURI()).toString();
    }

    @Test
    void looksUpCountryAndCityOffline() throws Exception {
        GeoIpService geo = new GeoIpService(testDatabase());

        GeoLocation where = geo.lookup("8.8.8.8").orElseThrow();
        assertEquals("Testland", where.country());
        assertEquals("ZZ", where.countryCode());
        assertEquals("Test City", where.city());
        assertEquals("DBIP-City-Lite", geo.source());

        GeoLocation countryOnly = geo.lookup("9.9.9.9").orElseThrow();
        assertEquals("Otherland", countryOnly.country());
        assertNull(countryOnly.city());

        assertTrue(geo.lookup("1.1.1.1").isEmpty(), "not in the database");
        assertTrue(geo.lookup("192.168.1.1").isEmpty(), "private addresses are never looked up");
        assertTrue(geo.lookup("dns.google").isEmpty(), "host names are never resolved");
        geo.close();
    }

    @Test
    void aMissingOrBrokenDatabaseSwitchesGeoIpOff(@TempDir Path dir) throws Exception {
        GeoIpService missing = new GeoIpService(dir.resolve("nope.mmdb").toString());
        assertNull(missing.source());
        assertTrue(missing.lookup("8.8.8.8").isEmpty());

        Path broken = dir.resolve("broken.mmdb");
        Files.writeString(broken, "not a database");
        GeoIpService corrupt = new GeoIpService(broken.toString());
        assertNull(corrupt.source());
        assertTrue(corrupt.lookup("8.8.8.8").isEmpty());

        assertNull(new GeoIpService("").source());
    }
}
