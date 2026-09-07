package com.cyberkit.app.core.model

import java.util.UUID

enum class FindingSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    val scorePenalty: Int
        get() = when (this) {
            INFO -> 0
            LOW -> 3
            MEDIUM -> 10
            HIGH -> 25
            CRITICAL -> 40
        }
}

enum class FindingConfidence {
    LOW,
    MEDIUM,
    HIGH
}

data class Finding(
    val id: String = UUID.randomUUID().toString(),
    val severity: FindingSeverity,
    val title: String,
    val description: String,
    val evidence: String = "",
    val target: String,
    val module: String,
    val remediation: String = "",
    val confidence: FindingConfidence = FindingConfidence.HIGH,
    val timestamp: Long = System.currentTimeMillis()
)

data class AssessmentSummary(
    val title: String,
    val target: String,
    val module: String,
    val score: Int, // 0 - 100
    val findings: List<Finding>,
    val metadata: Map<String, String> = emptyMap(),
    val timestamp: Long = System.currentTimeMillis()
) {
    val criticalCount: Int get() = findings.count { it.severity == FindingSeverity.CRITICAL }
    val highCount: Int get() = findings.count { it.severity == FindingSeverity.HIGH }
    val mediumCount: Int get() = findings.count { it.severity == FindingSeverity.MEDIUM }
    val lowCount: Int get() = findings.count { it.severity == FindingSeverity.LOW }
    val infoCount: Int get() = findings.count { it.severity == FindingSeverity.INFO }

    companion object {
        fun calculateScore(findings: List<Finding>): Int {
            var score = 100
            for (f in findings) {
                score -= f.severity.scorePenalty
            }
            return score.coerceIn(0, 100)
        }
    }
}
