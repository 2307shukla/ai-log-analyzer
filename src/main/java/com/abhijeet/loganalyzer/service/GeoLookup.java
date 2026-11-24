package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.GeoLocation;

import java.util.Optional;

/** Looks up where a public address is. Implementations must never call the network. */
public interface GeoLookup {

    /** The location of a public address, or empty when unknown or GeoIP is unavailable. */
    Optional<GeoLocation> lookup(String ip);

    /** A short description of the data source, or null when GeoIP is unavailable. */
    String source();

    GeoLookup NONE = new GeoLookup() {
        @Override
        public Optional<GeoLocation> lookup(String ip) {
            return Optional.empty();
        }

        @Override
        public String source() {
            return null;
        }
    };
}
