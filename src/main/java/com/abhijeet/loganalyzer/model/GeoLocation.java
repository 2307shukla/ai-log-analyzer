package com.abhijeet.loganalyzer.model;

/** Country and city for an address, from the offline GeoIP database. Any field may be null. */
public record GeoLocation(String country, String countryCode, String city) {
}
