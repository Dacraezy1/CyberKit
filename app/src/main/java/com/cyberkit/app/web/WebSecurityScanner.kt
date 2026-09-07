package com.cyberkit.app.web

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

class WebSecurityScanner {

    private val httpClient = OkHttpClient.Builder()
        .followRedirects(false)
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    suspend fun auditWebTarget(targetUrl: String): AssessmentSummary = withContext(Dispatchers.IO) {
        val findings = mutableListOf<Finding>()
        val cleanUrl = if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            "https://$targetUrl"
        } else targetUrl

        // 1. Check HTTP to HTTPS redirect enforcement
        val httpUrl = cleanUrl.replaceFirst("https://", "http://")
        try {
            val req = Request.Builder().url(httpUrl).build()
            httpClient.newCall(req).execute().use { resp ->
                if (resp.isRedirect) {
                    val loc = resp.header("Location") ?: ""
                    if (!loc.startsWith("https://")) {
                        findings.add(
                            Finding(
                                severity = FindingSeverity.HIGH,
                                title = "HTTP Does Not Redirect to HTTPS",
                                description = "Cleartext HTTP request redirects to a non-HTTPS destination: $loc",
                                evidence = "Location: $loc",
                                target = targetUrl,
                                module = "Web Security",
                                remediation = "Ensure port 80 strictly redirects to https:// equivalent using HTTP 301 Permanent Redirect.",
                                confidence = FindingConfidence.HIGH
                            )
                        )
                    }
                } else if (resp.isSuccessful) {
                    findings.add(
                        Finding(
                            severity = FindingSeverity.HIGH,
                            title = "Plain HTTP Service Actively Serves Content",
                            description = "HTTP request was answered with status 200 without redirecting to HTTPS.",
                            evidence = "Status: ${resp.code} on $httpUrl",
                            target = targetUrl,
                            module = "Web Security",
                            remediation = "Disable cleartext web serving and enforce 301 redirects to HTTPS.",
                            confidence = FindingConfidence.HIGH
                        )
                    )
                }
                Unit
            }
        } catch (_: Exception) {}

        // 2. Check for CORS Wildcard Configuration
        try {
            val corsReq = Request.Builder()
                .url(cleanUrl)
                .header("Origin", "https://attacker.example.com")
                .build()
            httpClient.newCall(corsReq).execute().use { resp ->
                val acao = resp.header("Access-Control-Allow-Origin")
                val acac = resp.header("Access-Control-Allow-Credentials")
                if (acao == "*" && acac.equals("true", ignoreCase = true)) {
                    findings.add(
                        Finding(
                            severity = FindingSeverity.CRITICAL,
                            title = "Overly Permissive CORS with Credentials Allowed",
                            description = "Server allows wildcard Origin with credentials (cookies/auth) enabled, violating security policies.",
                            evidence = "Access-Control-Allow-Origin: $acao, Allow-Credentials: $acac",
                            target = targetUrl,
                            module = "Web Security",
                            remediation = "Explicitly whitelist trusted origins instead of using wildcard or echoing arbitrary Origin headers.",
                            confidence = FindingConfidence.HIGH
                        )
                    )
                } else if (acao == "https://attacker.example.com") {
                    findings.add(
                        Finding(
                            severity = FindingSeverity.HIGH,
                            title = "Insecure CORS Origin Reflection",
                            description = "Server reflects arbitrary Origin headers in Access-Control-Allow-Origin.",
                            evidence = "Reflected Origin: $acao",
                            target = targetUrl,
                            module = "Web Security",
                            remediation = "Validate Origin against an explicit server-side whitelist.",
                            confidence = FindingConfidence.HIGH
                        )
                    )
                }
                Unit
            }
        } catch (_: Exception) {}

        val score = AssessmentSummary.calculateScore(findings)
        AssessmentSummary(
            title = "Web Security Audit: $cleanUrl",
            target = cleanUrl,
            module = "Web Security",
            score = score,
            findings = findings
        )
    }
}
