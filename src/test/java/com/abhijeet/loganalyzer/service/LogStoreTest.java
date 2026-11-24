package com.abhijeet.loganalyzer.service;

import com.abhijeet.loganalyzer.model.LogEvent;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogStoreTest {

    private static List<LogEvent> events(String ip) {
        return List.of(new LogEvent(ip, "GET", "/", 200, "ua", false, "raw"));
    }

    @Test
    void startsEmpty() {
        LogStore store = new LogStore();
        assertTrue(store.isEmpty("any-session"));
        assertTrue(store.isEmpty(null));
    }

    @Test
    void visitorsWithoutAnUploadSeeTheSample() {
        LogStore store = new LogStore();
        store.setSample("sample.log", events("1.1.1.1"));

        assertEquals("sample.log", store.name("nobody"));
        assertEquals("sample.log", store.name(null));
        assertFalse(store.isEmpty("nobody"));
    }

    @Test
    void uploadsAreIsolatedPerSession() {
        LogStore store = new LogStore();
        store.setSample("sample.log", events("1.1.1.1"));

        store.set("alice", "alice.log", events("2.2.2.2"));
        store.set("bob", "bob.log", events("3.3.3.3"));

        assertEquals("alice.log", store.name("alice"));
        assertEquals("2.2.2.2", store.get("alice").get(0).ip());
        assertEquals("bob.log", store.name("bob"));
        // A third visitor still sees only the sample, never another visitor's file.
        assertEquals("sample.log", store.name("carol"));
    }

    @Test
    void oldestUploadsAreEvictedToBoundMemory() {
        LogStore store = new LogStore();
        store.setSample("sample.log", events("1.1.1.1"));

        for (int i = 0; i <= LogStore.MAX_SESSIONS; i++) {
            store.set("s" + i, "f" + i + ".log", events("9.9.9." + i));
        }

        // The first session was evicted and falls back to the sample; the newest is kept.
        assertEquals("sample.log", store.name("s0"));
        assertEquals("f" + LogStore.MAX_SESSIONS + ".log", store.name("s" + LogStore.MAX_SESSIONS));
    }
}
