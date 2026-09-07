package com.cyberkit.app.files

import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

data class SecretMatch(
    val ruleName: String,
    val severity: FindingSeverity,
    val lineNumber: Int,
    val filePath: String,
    val maskedSnippet: String,
    val description: String
)

object SecretScanner {

    data class SecretPattern(
        val name: String,
        val regex: Regex,
        val severity: FindingSeverity,
        val description: String
    )

    private val RULES = listOf(
        SecretPattern(
            name = "AWS Access Key ID",
            regex = Regex("(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            severity = FindingSeverity.CRITICAL,
            description = "Amazon Web Services API access key detected"
        ),
        SecretPattern(
            name = "GitHub Personal Access Token",
            regex = Regex("(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
            severity = FindingSeverity.CRITICAL,
            description = "GitHub personal/OAuth access token detected"
        ),
        SecretPattern(
            name = "Google API Key",
            regex = Regex("AIza[0-9A-Za-z\\-_]{35}"),
            severity = FindingSeverity.HIGH,
            description = "Google cloud/service API key"
        ),
        SecretPattern(
            name = "Slack Bot/User Token",
            regex = Regex("xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}"),
            severity = FindingSeverity.HIGH,
            description = "Slack authentication token"
        ),
        SecretPattern(
            name = "Stripe Live Secret Key",
            regex = Regex("sk_live_[0-9a-zA-Z]{24,34}"),
            severity = FindingSeverity.CRITICAL,
            description = "Live payment gateway secret token"
        ),
        SecretPattern(
            name = "RSA/EC Private Key Header",
            regex = Regex("-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            severity = FindingSeverity.CRITICAL,
            description = "Asymmetric cryptographic private key block"
        ),
        SecretPattern(
            name = "Database Connection URI with Password",
            regex = Regex("(?:postgres|mysql|mongodb|redis)://[^:]+:([^@]+)@"),
            severity = FindingSeverity.HIGH,
            description = "Hardcoded database connection string with embedded plaintext credentials"
        ),
        SecretPattern(
            name = "JSON Web Token (JWT)",
            regex = Regex("eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]+"),
            severity = FindingSeverity.MEDIUM,
            description = "Encoded JSON Web Token authorization payload"
        )
    )

    suspend fun scanTextFile(file: File): List<SecretMatch> = withContext(Dispatchers.IO) {
        val matches = mutableListOf<SecretMatch>()
        if (!file.exists() || file.length() > 5_000_000) return@withContext emptyList() // Cap at 5MB for responsiveness

        try {
            file.bufferedReader().useLines { lines ->
                var lineNo = 1
                for (line in lines) {
                    for (rule in RULES) {
                        val matchResult = rule.regex.find(line)
                        if (matchResult != null) {
                            val raw = matchResult.value
                            val masked = if (raw.length > 8) {
                                "${raw.take(4)}...${raw.takeLast(4)}"
                            } else "****"
                            matches.add(
                                SecretMatch(
                                    ruleName = rule.name,
                                    severity = rule.severity,
                                    lineNumber = lineNo,
                                    filePath = file.name,
                                    maskedSnippet = masked,
                                    description = rule.description
                                )
                            )
                        }
                    }
                    lineNo++
                }
            }
        } catch (_: Exception) {}

        matches
    }

    fun toFindings(matches: List<SecretMatch>, targetName: String): List<Finding> {
        return matches.map { m ->
            Finding(
                severity = m.severity,
                title = "Secret Detected: ${m.ruleName}",
                description = "${m.description} found in ${m.filePath} at line ${m.lineNumber}.",
                evidence = "Line ${m.lineNumber}: ${m.maskedSnippet}",
                target = "$targetName:${m.lineNumber}",
                module = "Secret Scanner",
                remediation = "Remove hardcoded secret from repository, rotate the exposed credential immediately, and load secrets dynamically from secure environment variables or vault.",
                confidence = FindingConfidence.HIGH
            )
        }
    }
}
