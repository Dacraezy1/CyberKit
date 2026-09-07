package com.cyberkit.app

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import com.cyberkit.app.reports.ReportGenerator
import org.junit.Assert.*
import org.junit.Test

class ReportGeneratorTest {

    private fun sampleSummary(): AssessmentSummary {
        val finding1 = Finding(
            severity = FindingSeverity.HIGH,
            title = "Insecure Telnet Service",
            description = "Telnet transmits plain text",
            evidence = "Port 23 OPEN",
            target = "192.168.1.1:23",
            module = "Port Scanner",
            remediation = "Use SSH instead",
            confidence = FindingConfidence.HIGH
        )
        return AssessmentSummary(
            title = "Test Port Scan",
            target = "192.168.1.1",
            module = "Port Scanner",
            score = 75,
            findings = listOf(finding1),
            metadata = mapOf("Scan Type" to "Full TCP")
        )
    }

    @Test
    fun testJsonExport() {
        val json = ReportGenerator.exportToJson(sampleSummary())
        assertTrue(json.contains("\"title\": \"Test Port Scan\""))
        assertTrue(json.contains("\"target\": \"192.168.1.1\""))
        assertTrue(json.contains("\"securityScore\": 75"))
        assertTrue(json.contains("\"severity\": \"HIGH\""))
    }

    @Test
    fun testCsvExport() {
        val csv = ReportGenerator.exportToCsv(sampleSummary())
        assertTrue(csv.startsWith("Severity,Title,Target,Module,Confidence,Description,Evidence,Remediation"))
        assertTrue(csv.contains("\"HIGH\",\"Insecure Telnet Service\""))
    }

    @Test
    fun testHtmlExport() {
        val html = ReportGenerator.exportToHtml(sampleSummary())
        assertTrue(html.contains("<!DOCTYPE html>"))
        assertTrue(html.contains("Test Port Scan"))
        assertTrue(html.contains("Insecure Telnet Service"))
        assertTrue(html.contains("Port 23 OPEN"))
    }

    @Test
    fun testTxtExport() {
        val txt = ReportGenerator.exportToTxt(sampleSummary())
        assertTrue(txt.contains("CYBERKIT SECURITY ASSESSMENT REPORT"))
        assertTrue(txt.contains("Target:        192.168.1.1"))
        assertTrue(txt.contains("[HIGH] Insecure Telnet Service"))
    }
}
