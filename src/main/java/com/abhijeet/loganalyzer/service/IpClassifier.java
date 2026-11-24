package com.abhijeet.loganalyzer.service;

import java.util.regex.Pattern;

/**
 * Says what kind of network an address belongs to, without any lookup. Only "Public" addresses
 * are worth a GeoIP lookup; the rest have no location.
 */
public final class IpClassifier {

    public static final String PUBLIC = "Public";

    private static final Pattern IPV4 = Pattern.compile(
            "^(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:]{2,39}$");

    private IpClassifier() {
    }

    /** True for a literal IPv4 or IPv6 address, never a host name (so no DNS lookup can happen). */
    public static boolean isLiteral(String ip) {
        return ip != null && (IPV4.matcher(ip).matches() || (ip.contains(":") && IPV6.matcher(ip).matches()));
    }

    public static String classify(String ip) {
        if (!isLiteral(ip)) {
            return "Not an address";
        }
        if (ip.contains(":")) {
            String v6 = ip.toLowerCase();
            if (v6.equals("::1")) {
                return "Loopback";
            }
            if (v6.startsWith("fe8") || v6.startsWith("fe9") || v6.startsWith("fea") || v6.startsWith("feb")) {
                return "Link-local";
            }
            if (v6.startsWith("fc") || v6.startsWith("fd")) {
                return "Private network";
            }
            if (v6.startsWith("2001:db8:") || v6.startsWith("2001:0db8:")) {
                return "Documentation range";
            }
            return PUBLIC;
        }
        String[] p = ip.split("\\.");
        int a = Integer.parseInt(p[0]);
        int b = Integer.parseInt(p[1]);
        int c = Integer.parseInt(p[2]);
        if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)) {
            return "Private network";
        }
        if (a == 127) {
            return "Loopback";
        }
        if (a == 169 && b == 254) {
            return "Link-local";
        }
        if (a == 100 && b >= 64 && b <= 127) {
            return "Carrier-grade NAT";
        }
        if ((a == 192 && b == 0 && c == 2) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113)) {
            return "Documentation range";
        }
        if (a == 0 || a >= 224 || (a == 198 && (b == 18 || b == 19)) || (a == 192 && b == 0 && c == 0)) {
            return "Reserved";
        }
        return PUBLIC;
    }
}
