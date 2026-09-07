package com.cyberkit.app.web

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.URI
import java.net.URLDecoder
import java.util.concurrent.TimeUnit

data class UrlSyntaxInfo(
    val rawUrl: String,
    val scheme: String,
    val host: String,
    val port: Int,
    val path: String,
    val queryParamsCount: Int,
    val isPunycode: Boolean,
    val isRawIp: Boolean,
    val hasEmbeddedCredentials: Boolean,
    val isUnusualPort: Boolean
)

data class RedirectHop(
    val url: String,
    val statusCode: Int
)

data class CookieAudit(
    val name: String,
    val isSecure: Boolean,
    val isHttpOnly: Boolean,
    val sameSite: String?
)

data class UrlAnalysisResult(
    val syntax: UrlSyntaxInfo,
    val finalStatusCode: Int,
    val redirects: List<RedirectHop>,
    val responseHeaders: Map<String, String>,
    val securityHeaders: Map<String, Boolean>,
    val cookies: List<CookieAudit>,
    val serverBanner: String?,
    val poweredByBanner: String?
)

class UrlAnalyzer {

    private val httpClient = OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .build()

    suspend fun analyzeUrl(inputUrl: String): UrlAnalysisResult = withContext(Dispatchers.IO) {
        val target = if (!inputUrl.startsWith("http://") && !inputUrl.startsWith("https://")) {
            "https://$inputUrl"
        } else {
            inputUrl
        }

        val uri = URI(target)
        val scheme = uri.scheme ?: "http"
        val host = uri.host ?: ""
        val port = if (uri.port != -1) uri.port else if (scheme == "https") 443 else 80
        val path = uri.path.ifEmpty { "/" }
        val queryCount = uri.query?.split("&")?.size ?: 0

        val isPuny = host.startsWith("xn--") || host.contains(".xn--")
        val isIp = host.matches(Regex("^(\\d{1,3}\\.){3}\\d{1,3}$"))
        val hasCreds = uri.userInfo != null
        val isUnusualPort = port !in listOf(80, 443, 8080, 8443)

        val syntax = UrlSyntaxInfo(
            rawUrl = inputUrl,
            scheme = scheme,
            host = host,
            port = port,
            path = path,
            queryParamsCount = queryCount,
            isPunycode = isPuny,
            isRawIp = isIp,
            hasEmbeddedCredentials = hasCreds,
            isUnusualPort = isUnusualPort
        )

        // Trace redirects up to 5 hops
        var currentUrl = target
        val redirectList = mutableListOf<RedirectHop>()
        var finalHeaders = emptyMap<String, String>()
        var finalStatus = -1
        val cookies = mutableListOf<CookieAudit>()

        for (hop in 0 until 5) {
            try {
                val req = Request.Builder()
                    .url(currentUrl)
                    .header("User-Agent", "Mozilla/5.0 (Android; CyberKit Security Assessment/1.0)")
                    .build()

                val response = httpClient.newCall(req).execute()
                var shouldStop = false
                try {
                    finalStatus = response.code
                    redirectList.add(RedirectHop(currentUrl, response.code))

                    // Extract headers
                    val headerMap = mutableMapOf<String, String>()
                    for (name in response.headers.names()) {
                        headerMap[name] = response.header(name) ?: ""
                    }
                    finalHeaders = headerMap

                    // Extract cookies
                    for (header in response.headers("Set-Cookie")) {
                        cookies.add(parseCookie(header))
                    }

                    if (response.isRedirect) {
                        val next = response.header("Location")
                        if (!next.isNullOrBlank()) {
                            currentUrl = URI(currentUrl).resolve(next).toString()
                        } else {
                            shouldStop = true
                        }
                    } else {
                        shouldStop = true
                    }
                } finally {
                    response.close()
                }
                if (shouldStop) break
            } catch (e: Exception) {
                if (finalStatus == -1) finalStatus = 0
                break
            }
        }

        val secHeaders = mapOf(
            "Strict-Transport-Security" to finalHeaders.containsKey("strict-transport-security"),
            "Content-Security-Policy" to finalHeaders.containsKey("content-security-policy"),
            "X-Frame-Options" to finalHeaders.containsKey("x-frame-options"),
            "X-Content-Type-Options" to finalHeaders.containsKey("x-content-type-options"),
            "Referrer-Policy" to finalHeaders.containsKey("referrer-policy"),
            "Permissions-Policy" to finalHeaders.containsKey("permissions-policy")
        )

        val server = finalHeaders["server"]
        val poweredBy = finalHeaders["x-powered-by"]

        UrlAnalysisResult(
            syntax = syntax,
            finalStatusCode = finalStatus,
            redirects = redirectList,
            responseHeaders = finalHeaders,
            securityHeaders = secHeaders,
            cookies = cookies,
            serverBanner = server,
            poweredByBanner = poweredBy
        )
    }

    private fun parseCookie(header: String): CookieAudit {
        val parts = header.split(";").map { it.trim() }
        val name = parts.firstOrNull()?.split("=")?.firstOrNull() ?: "Unknown"
        val isSecure = parts.any { it.equals("Secure", ignoreCase = true) }
        val isHttpOnly = parts.any { it.equals("HttpOnly", ignoreCase = true) }
        val sameSite = parts.firstOrNull { it.startsWith("SameSite=", ignoreCase = true) }?.split("=")?.getOrNull(1)
        return CookieAudit(name, isSecure, isHttpOnly, sameSite)
    }

    fun generateAssessmentSummary(result: UrlAnalysisResult): AssessmentSummary {
        val findings = mutableListOf<Finding>()
        val url = result.syntax.rawUrl

        // Syntax checks
        if (result.syntax.isPunycode) {
            findings.add(
                Finding(
                    severity = FindingSeverity.HIGH,
                    title = "Punycode / IDN Homograph Domain Detected",
                    description = "Domain uses internationalized characters (${result.syntax.host}). Often abused for visual spoofing and phishing.",
                    evidence = "Hostname: ${result.syntax.host}",
                    target = url,
                    module = "URL Checker",
                    remediation = "Confirm domain legitimacy before interacting with sensitive services.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (result.syntax.isRawIp) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "Raw IP Address Hostname Used",
                    description = "Direct IP connection bypassing domain name system and standard TLS SNI validation.",
                    evidence = "Host: ${result.syntax.host}",
                    target = url,
                    module = "URL Checker",
                    remediation = "Use fully qualified domain names with trusted TLS certificates.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (result.syntax.scheme != "https") {
            findings.add(
                Finding(
                    severity = FindingSeverity.HIGH,
                    title = "Cleartext HTTP Protocol in Use",
                    description = "Connection is initiated over unencrypted HTTP. Data in transit is subject to eavesdropping and tampering.",
                    evidence = "Scheme: ${result.syntax.scheme}",
                    target = url,
                    module = "URL Checker",
                    remediation = "Enforce HTTPS communication across all endpoints.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // Security headers
        if (result.securityHeaders["Strict-Transport-Security"] == false && result.syntax.scheme == "https") {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "Missing HTTP Strict Transport Security (HSTS)",
                    description = "Without HSTS, clients may be downgraded to cleartext HTTP via SSL stripping attacks.",
                    evidence = "Header 'Strict-Transport-Security' missing",
                    target = url,
                    module = "URL Checker",
                    remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (result.securityHeaders["Content-Security-Policy"] == false) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "Missing Content Security Policy (CSP)",
                    description = "No CSP header detected. CSP restricts authorized script/resource execution and mitigates Cross-Site Scripting (XSS).",
                    evidence = "Header 'Content-Security-Policy' missing",
                    target = url,
                    module = "URL Checker",
                    remediation = "Configure a Content-Security-Policy header limiting script-src and object-src.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (result.securityHeaders["X-Frame-Options"] == false) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Missing Clickjacking Protection (X-Frame-Options)",
                    description = "Pages without framing restrictions may be embedded into malicious iframes (Clickjacking).",
                    evidence = "Header 'X-Frame-Options' missing",
                    target = url,
                    module = "URL Checker",
                    remediation = "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors'.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (result.securityHeaders["X-Content-Type-Options"] == false) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Missing MIME-Sniffing Protection",
                    description = "Missing X-Content-Type-Options allows browsers to MIME-sniff response bodies, potentially executing scripts disguised as images or text.",
                    evidence = "Header 'X-Content-Type-Options' missing",
                    target = url,
                    module = "URL Checker",
                    remediation = "Set 'X-Content-Type-Options: nosniff'.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // Information disclosure
        if (result.serverBanner != null && result.serverBanner.matches(Regex(".*[0-9].*"))) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Detailed Server Version Disclosed",
                    description = "The Server response header discloses specific software and version numbers, aiding attacker reconnaissance.",
                    evidence = "Server: ${result.serverBanner}",
                    target = url,
                    module = "URL Checker",
                    remediation = "Mask or remove version numbers from server banners (e.g. server_tokens off in nginx).",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (result.poweredByBanner != null) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Technology Stack Disclosed (X-Powered-By)",
                    description = "Header leaks backend framework or runtime information.",
                    evidence = "X-Powered-By: ${result.poweredByBanner}",
                    target = url,
                    module = "URL Checker",
                    remediation = "Disable X-Powered-By headers in web server or application framework settings.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // Cookies
        for (c in result.cookies) {
            if (!c.isSecure && result.syntax.scheme == "https") {
                findings.add(
                    Finding(
                        severity = FindingSeverity.MEDIUM,
                        title = "Cookie Missing 'Secure' Attribute (${c.name})",
                        description = "Cookie '${c.name}' lacks the Secure flag and can be transmitted over unencrypted connections.",
                        evidence = "Cookie: ${c.name}",
                        target = url,
                        module = "URL Checker",
                        remediation = "Set the Secure attribute on all sensitive session cookies.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }
            if (!c.isHttpOnly) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.LOW,
                        title = "Cookie Missing 'HttpOnly' Attribute (${c.name})",
                        description = "Cookie '${c.name}' can be accessed via client-side JavaScript (document.cookie), increasing XSS exploitation impact.",
                        evidence = "Cookie: ${c.name}",
                        target = url,
                        module = "URL Checker",
                        remediation = "Add the HttpOnly attribute to prevent JavaScript access.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }
        }

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "URL Assessment: ${result.syntax.host}",
            target = url,
            module = "URL Checker",
            score = score,
            findings = findings,
            metadata = mapOf(
                "Final HTTP Status" to result.finalStatusCode.toString(),
                "Redirect Count" to result.redirects.size.toString(),
                "Cookies Audited" to result.cookies.size.toString(),
                "Scheme" to result.syntax.scheme
            )
        )
    }
}
