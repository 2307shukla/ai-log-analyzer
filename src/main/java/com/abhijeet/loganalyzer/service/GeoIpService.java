package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.GeoLocation;
import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.net.InetAddress;
import java.util.Optional;

/**
 * GeoIP from an offline MaxMind-format database, normally the free DB-IP City Lite file
 * (CC BY 4.0, no account or key). The file is memory-mapped, so it does not count against the
 * Java heap. If the file is missing or unreadable, GeoIP is simply switched off: every lookup
 * returns empty and the rest of the analysis is unchanged. No lookup ever leaves the machine.
 */
@Service
public class GeoIpService implements GeoLookup {

    private static final Logger log = LoggerFactory.getLogger(GeoIpService.class);

    private final DatabaseReader reader;
    private final String source;

    public GeoIpService(@Value("${geoip.database:}") String path) {
        DatabaseReader opened = null;
        String description = null;
        if (path != null && !path.isBlank()) {
            File file = new File(path);
            if (file.isFile() && file.length() > 0) {
                try {
                    opened = new DatabaseReader.Builder(file)
                            .fileMode(Reader.FileMode.MEMORY_MAPPED)
                            .withCache(new CHMCache())
                            .build();
                    description = opened.getMetadata().getDatabaseType();
                    log.info("GeoIP enabled: {} ({})", description, file.getName());
                } catch (Exception e) {
                    log.warn("GeoIP disabled: could not open {}: {}", path, e.getMessage());
                }
            } else {
                log.info("GeoIP disabled: {} not found", path);
            }
        } else {
            log.info("GeoIP disabled: no database configured (geoip.database)");
        }
        this.reader = opened;
        this.source = description;
    }

    @Override
    public Optional<GeoLocation> lookup(String ip) {
        if (reader == null || !IpClassifier.PUBLIC.equals(IpClassifier.classify(ip))) {
            return Optional.empty();
        }
        try {
            // A literal address: InetAddress parses it without any DNS query.
            Optional<CityResponse> found = reader.tryCity(InetAddress.getByName(ip));
            return found.map(r -> new GeoLocation(
                    r.getCountry() == null ? null : r.getCountry().getName(),
                    r.getCountry() == null ? null : r.getCountry().getIsoCode(),
                    r.getCity() == null ? null : r.getCity().getName()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public String source() {
        return source;
    }

    @PreDestroy
    void close() {
        if (reader != null) {
            try {
                reader.close();
            } catch (Exception ignored) {
                // shutting down
            }
        }
    }
}
