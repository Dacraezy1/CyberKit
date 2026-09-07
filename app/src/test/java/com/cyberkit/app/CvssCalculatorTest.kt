package com.cyberkit.app

import com.cyberkit.app.cvss.CvssCalculator
import com.cyberkit.app.cvss.CvssMetrics
import com.cyberkit.app.cvss.CvssSeverity
import org.junit.Assert.*
import org.junit.Test

class CvssCalculatorTest {

    @Test
    fun testCriticalCvssVector() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> Base Score 9.8
        val metrics = CvssMetrics(
            attackVector = "N",
            attackComplexity = "L",
            privilegesRequired = "N",
            userInteraction = "N",
            scope = "U",
            confidentiality = "H",
            integrity = "H",
            availability = "H"
        )
        val result = CvssCalculator.calculate(metrics)
        assertEquals(9.8, result.baseScore, 0.1)
        assertEquals(CvssSeverity.CRITICAL, result.severity)
    }

    @Test
    fun testMediumCvssVectorXss() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> Base Score 6.1
        val metrics = CvssMetrics(
            attackVector = "N",
            attackComplexity = "L",
            privilegesRequired = "N",
            userInteraction = "R",
            scope = "C",
            confidentiality = "L",
            integrity = "L",
            availability = "N"
        )
        val result = CvssCalculator.calculate(metrics)
        assertEquals(6.1, result.baseScore, 0.1)
        assertEquals(CvssSeverity.MEDIUM, result.severity)
    }

    @Test
    fun testNoneImpactVector() {
        val metrics = CvssMetrics(
            attackVector = "N",
            attackComplexity = "L",
            privilegesRequired = "N",
            userInteraction = "N",
            scope = "U",
            confidentiality = "N",
            integrity = "N",
            availability = "N"
        )
        val result = CvssCalculator.calculate(metrics)
        assertEquals(0.0, result.baseScore, 0.0)
        assertEquals(CvssSeverity.NONE, result.severity)
    }
}
