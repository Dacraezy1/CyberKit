package com.cyberkit.app.cvss

import kotlin.math.ceil
import kotlin.math.min
import kotlin.math.pow

enum class CvssSeverity {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

data class CvssMetrics(
    val attackVector: String = "N",        // N, A, L, P
    val attackComplexity: String = "L",    // L, H
    val privilegesRequired: String = "N",  // N, L, H
    val userInteraction: String = "N",     // N, R
    val scope: String = "U",               // U, C
    val confidentiality: String = "H",     // N, L, H
    val integrity: String = "H",           // N, L, H
    val availability: String = "H"         // N, L, H
)

data class CvssResult(
    val baseScore: Double,
    val severity: CvssSeverity,
    val vectorString: String,
    val impactSubScore: Double,
    val exploitabilitySubScore: Double,
    val explanation: String
)

object CvssCalculator {

    fun calculate(metrics: CvssMetrics): CvssResult {
        val av = when (metrics.attackVector) {
            "N" -> 0.85
            "A" -> 0.62
            "L" -> 0.55
            "P" -> 0.20
            else -> 0.85
        }

        val ac = when (metrics.attackComplexity) {
            "L" -> 0.77
            "H" -> 0.44
            else -> 0.77
        }

        val pr = when (metrics.privilegesRequired) {
            "N" -> 0.85
            "L" -> if (metrics.scope == "C") 0.68 else 0.62
            "H" -> if (metrics.scope == "C") 0.50 else 0.27
            else -> 0.85
        }

        val ui = when (metrics.userInteraction) {
            "N" -> 0.85
            "R" -> 0.62
            else -> 0.85
        }

        val c = when (metrics.confidentiality) {
            "H" -> 0.56
            "L" -> 0.22
            else -> 0.0
        }

        val i = when (metrics.integrity) {
            "H" -> 0.56
            "L" -> 0.22
            else -> 0.0
        }

        val a = when (metrics.availability) {
            "H" -> 0.56
            "L" -> 0.22
            else -> 0.0
        }

        val iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        val impact = if (metrics.scope == "U") {
            6.42 * iss
        } else {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).pow(15)
        }

        val exploitability = 8.22 * av * ac * pr * ui

        val baseScore = if (impact <= 0.0) {
            0.0
        } else {
            if (metrics.scope == "U") {
                roundUp1(min(impact + exploitability, 10.0))
            } else {
                roundUp1(min(1.08 * (impact + exploitability), 10.0))
            }
        }

        val severity = when {
            baseScore == 0.0 -> CvssSeverity.NONE
            baseScore <= 3.9 -> CvssSeverity.LOW
            baseScore <= 6.9 -> CvssSeverity.MEDIUM
            baseScore <= 8.9 -> CvssSeverity.HIGH
            else -> CvssSeverity.CRITICAL
        }

        val vector = "CVSS:3.1/AV:${metrics.attackVector}/AC:${metrics.attackComplexity}/PR:${metrics.privilegesRequired}/UI:${metrics.userInteraction}/S:${metrics.scope}/C:${metrics.confidentiality}/I:${metrics.integrity}/A:${metrics.availability}"

        val explanation = buildExplanation(metrics, baseScore, severity)

        return CvssResult(
            baseScore = baseScore,
            severity = severity,
            vectorString = vector,
            impactSubScore = String.format("%.1f", impact).toDoubleOrNull() ?: 0.0,
            exploitabilitySubScore = String.format("%.1f", exploitability).toDoubleOrNull() ?: 0.0,
            explanation = explanation
        )
    }

    private fun roundUp1(input: Double): Double {
        return ceil(input * 10.0) / 10.0
    }

    private fun buildExplanation(m: CvssMetrics, score: Double, sev: CvssSeverity): String {
        val avDesc = when (m.attackVector) {
            "N" -> "remotely over the network without physical proximity"
            "A" -> "from the adjacent network (e.g. local subnet / Bluetooth)"
            "L" -> "locally via local user account or application shell"
            else -> "through direct physical tampering"
        }
        val prDesc = when (m.privilegesRequired) {
            "N" -> "without prior authentication"
            "L" -> "with standard non-privileged user access"
            else -> "with high administrative/root privileges"
        }
        val uiDesc = if (m.userInteraction == "R") "requires victim interaction" else "requires no user interaction"

        return "This vulnerability rates $score ($sev). It can be exploited $avDesc $prDesc and $uiDesc."
    }
}
