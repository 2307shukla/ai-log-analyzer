package com.abhijeet.loganalyzer.config;

import com.abhijeet.loganalyzer.model.LogEvent;
import com.abhijeet.loganalyzer.service.LogParser;
import com.abhijeet.loganalyzer.service.LogStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Loads the bundled sample log at startup so the dashboard has something to analyse.
 */
@Component
public class SampleLogLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SampleLogLoader.class);
    private static final String SAMPLE = "sample.log";

    private final LogParser parser;
    private final LogStore store;

    public SampleLogLoader(LogParser parser, LogStore store) {
        this.parser = parser;
        this.store = store;
    }

    @Override
    public void run(ApplicationArguments args) {
        ClassPathResource resource = new ClassPathResource(SAMPLE);

        if (!resource.exists()) {
            log.warn("{} not found on the classpath - starting with an empty log store", SAMPLE);
            return;
        }

        try (InputStream in = resource.getInputStream()) {
            String content = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            List<LogEvent> events = parser.parse(content);
            store.set(SAMPLE, events);
            log.info("Loaded {} with {} entries", SAMPLE, events.size());
        } catch (Exception e) {
            log.warn("Could not load {}: {}", SAMPLE, e.getMessage());
        }
    }
}
