package com.abhijeet.loganalyzer;

import com.abhijeet.loganalyzer.service.LogStore;
import com.abhijeet.loganalyzer.service.ReportCache;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ExportIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ReportCache reports;

    @Autowired
    private LogStore store;

    @Test
    void pdfDownload() throws Exception {
        byte[] pdf = mockMvc.perform(get("/api/logs/export").param("format", "pdf"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("log-analysis-report.pdf")))
                .andExpect(content().contentType("application/pdf"))
                .andReturn().getResponse().getContentAsByteArray();
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            String text = new PDFTextStripper().getText(doc);
            assertTrue(text.contains("Source: sample.log"));
            assertTrue(text.contains("brute-force-burst") || text.contains("More than 5 failed logins"));
        }
    }

    @Test
    void findingsAsCsv() throws Exception {
        mockMvc.perform(get("/api/logs/export").param("format", "csv"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("log-analysis-findings.csv")))
                .andExpect(content().contentTypeCompatibleWith("text/csv"))
                .andExpect(content().string(startsWith("severity,rule,title,mitre,count")))
                .andExpect(content().string(containsString("\"COMPROMISED_LOGIN\"")));
    }

    @Test
    void exportsReuseTheAiReportAlreadyWrittenForThisLog() throws Exception {
        reports.put(null, store.get(null), "## Executive summary\nCached report for the sample.");
        mockMvc.perform(get("/api/logs/export").param("format", "md"))
                .andExpect(content().string(containsString("Cached report for the sample.")));
        mockMvc.perform(get("/api/logs/export").param("format", "json"))
                .andExpect(content().string(containsString("Cached report for the sample.")));
    }

    @Test
    void unknownFormatListsTheChoices() throws Exception {
        mockMvc.perform(get("/api/logs/export").param("format", "docx"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("pdf, md, json or csv")));
    }
}
