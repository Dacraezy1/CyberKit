package com.cyberkit.app.web

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.interfaces.RSAKey
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

data class CertificateDetails(
    val subject: String,
    val issuer: String,
    val validFrom: Date,
    val validTo: Date,
    val daysRemaining: Long,
    val signatureAlgorithm: String,
    val publicKeyAlgorithm: String,
    val keySizeBits: Int,
    val sans: List<String>,
    val isSelfSigned: Boolean,
    val isExpired: Boolean
)

data class TlsAnalysisResult(
    val host: String,
    val port: Int,
    val protocol: String,
    val cipherSuite: String,
    val handshakeLatencyMs: Long,
    val isTrustedBySystemCa: Boolean,
    val trustErrorMessage: String? = null,
    val certificates: List<CertificateDetails>
)

class TlsAnalyzer {

    suspend fun analyzeTls(host: String, port: Int = 443, timeoutMs: Int = 5000): TlsAnalysisResult = withContext(Dispatchers.IO) {
        val cleanHost = host.trim().removePrefix("https://").removePrefix("http://").split("/")[0].split(":")[0]
        val startTime = System.currentTimeMillis()

        // 1. Handshake with trust-all to capture full certificate chain regardless of CA validity
        val collectedCerts = mutableListOf<X509Certificate>()
        var negotiatedProtocol = "Unknown"
        var negotiatedCipher = "Unknown"

        val trustAllContext = SSLContext.getInstance("TLS")
        trustAllContext.init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                chain?.let { collectedCerts.addAll(it) }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }), java.security.SecureRandom())

        (trustAllContext.socketFactory.createSocket() as SSLSocket).use { socket ->
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(cleanHost, port), timeoutMs)
            socket.startHandshake()
            val session = socket.session
            negotiatedProtocol = session.protocol
            negotiatedCipher = session.cipherSuite
            if (collectedCerts.isEmpty()) {
                session.peerCertificates.filterIsInstance<X509Certificate>().forEach { collectedCerts.add(it) }
            }
        }
        val handshakeLatency = System.currentTimeMillis() - startTime

        // 2. Validate against standard system CA trust managers
        var isTrusted = false
        var trustError: String? = null
        try {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            val defaultTm = tmf.trustManagers.firstOrNull { it is X509TrustManager } as? X509TrustManager
            defaultTm?.checkServerTrusted(collectedCerts.toTypedArray(), "RSA")
            isTrusted = true
        } catch (e: Exception) {
            isTrusted = false
            trustError = e.message ?: "Certificate chain could not be verified by system CAs"
        }

        val certDetailsList = collectedCerts.map { cert ->
            val now = System.currentTimeMillis()
            val daysRem = (cert.notAfter.time - now) / (1000 * 60 * 60 * 24)
            val isSelf = cert.subjectX500Principal == cert.issuerX500Principal
            var isExp = false
            try {
                cert.checkValidity()
            } catch (_: CertificateExpiredException) {
                isExp = true
            } catch (_: CertificateNotYetValidException) {
                isExp = true
            }

            val sans = mutableListOf<String>()
            try {
                cert.subjectAlternativeNames?.forEach { item ->
                    if (item.size > 1 && item[1] != null) {
                        sans.add(item[1].toString())
                    }
                }
            } catch (_: Exception) {}

            val keyBits = (cert.publicKey as? RSAKey)?.modulus?.bitLength() ?: -1

            CertificateDetails(
                subject = cert.subjectX500Principal.name,
                issuer = cert.issuerX500Principal.name,
                validFrom = cert.notBefore,
                validTo = cert.notAfter,
                daysRemaining = daysRem,
                signatureAlgorithm = cert.sigAlgName,
                publicKeyAlgorithm = cert.publicKey.algorithm,
                keySizeBits = keyBits,
                sans = sans,
                isSelfSigned = isSelf,
                isExpired = isExp
            )
        }

        TlsAnalysisResult(
            host = cleanHost,
            port = port,
            protocol = negotiatedProtocol,
            cipherSuite = negotiatedCipher,
            handshakeLatencyMs = handshakeLatency,
            isTrustedBySystemCa = isTrusted,
            trustErrorMessage = trustError,
            certificates = certDetailsList
        )
    }

    fun generateAssessmentSummary(result: TlsAnalysisResult): AssessmentSummary {
        val findings = mutableListOf<Finding>()
        val primaryCert = result.certificates.firstOrNull()

        if (!result.isTrustedBySystemCa) {
            findings.add(
                Finding(
                    severity = FindingSeverity.HIGH,
                    title = "Untrusted TLS Certificate",
                    description = "The TLS certificate chain is not trusted by the Android system CA store: ${result.trustErrorMessage}",
                    evidence = "Target: ${result.host}:${result.port}, Issuer: ${primaryCert?.issuer ?: "Unknown"}",
                    target = "${result.host}:${result.port}",
                    module = "TLS Analyzer",
                    remediation = "Replace with a valid certificate signed by an established trusted public Certificate Authority (e.g. Let's Encrypt).",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (primaryCert != null) {
            if (primaryCert.isExpired) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.CRITICAL,
                        title = "TLS Certificate Expired or Not Yet Valid",
                        description = "Certificate expired on ${primaryCert.validTo} (${primaryCert.daysRemaining} days remaining).",
                        evidence = "Validity: ${primaryCert.validFrom} to ${primaryCert.validTo}",
                        target = result.host,
                        module = "TLS Analyzer",
                        remediation = "Renew and deploy an active TLS certificate immediately.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            } else if (primaryCert.daysRemaining in 1..14) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.MEDIUM,
                        title = "TLS Certificate Expiring Soon",
                        description = "Certificate will expire in ${primaryCert.daysRemaining} day(s).",
                        evidence = "Valid until ${primaryCert.validTo}",
                        target = result.host,
                        module = "TLS Analyzer",
                        remediation = "Trigger certificate renewal workflow before expiration.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }

            if (primaryCert.isSelfSigned && result.certificates.size == 1) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.HIGH,
                        title = "Self-Signed Certificate Detected",
                        description = "Subject and Issuer are identical. Self-signed certificates allow Man-In-The-Middle interception unless pinned explicitly.",
                        evidence = "Subject: ${primaryCert.subject}",
                        target = result.host,
                        module = "TLS Analyzer",
                        remediation = "Use a trusted Certificate Authority in production environments.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }

            if (primaryCert.signatureAlgorithm.contains("SHA1", ignoreCase = true) ||
                primaryCert.signatureAlgorithm.contains("MD5", ignoreCase = true)) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.CRITICAL,
                        title = "Weak Certificate Signature Algorithm (${primaryCert.signatureAlgorithm})",
                        description = "SHA-1 and MD5 signature algorithms are cryptographically broken and prone to collision attacks.",
                        evidence = "Signature algorithm: ${primaryCert.signatureAlgorithm}",
                        target = result.host,
                        module = "TLS Analyzer",
                        remediation = "Re-issue certificate using SHA-256 or SHA-384 with RSA 2048+ or ECDSA.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }

            if (primaryCert.publicKeyAlgorithm == "RSA" && primaryCert.keySizeBits in 1..2047) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.HIGH,
                        title = "Short RSA Key Length (${primaryCert.keySizeBits} bits)",
                        description = "RSA keys shorter than 2048 bits do not provide adequate modern security margins.",
                        evidence = "Key size: ${primaryCert.keySizeBits} bits",
                        target = result.host,
                        module = "TLS Analyzer",
                        remediation = "Use at least RSA 2048 bits or ECDSA with curve P-256 / P-384.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }
        }

        if (result.protocol == "TLSv1" || result.protocol == "TLSv1.1") {
            findings.add(
                Finding(
                    severity = FindingSeverity.CRITICAL,
                    title = "Deprecated Protocol Negotiated (${result.protocol})",
                    description = "TLS 1.0 and 1.1 have been deprecated by IETF (RFC 8996) due to known cryptographic weaknesses.",
                    evidence = "Negotiated: ${result.protocol}",
                    target = result.host,
                    module = "TLS Analyzer",
                    remediation = "Disable TLS 1.0/1.1 and enforce TLS 1.2 and TLS 1.3.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (findings.none { it.severity == FindingSeverity.HIGH || it.severity == FindingSeverity.CRITICAL }) {
            findings.add(
                Finding(
                    severity = FindingSeverity.INFO,
                    title = "Modern TLS Protocol & Cipher",
                    description = "Negotiated ${result.protocol} using ${result.cipherSuite}. Handshake latency: ${result.handshakeLatencyMs}ms.",
                    evidence = "${result.protocol} - ${result.cipherSuite}",
                    target = result.host,
                    module = "TLS Analyzer",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "TLS Analysis: ${result.host}:${result.port}",
            target = "${result.host}:${result.port}",
            module = "TLS Analyzer",
            score = score,
            findings = findings,
            metadata = mapOf(
                "Protocol" to result.protocol,
                "Cipher Suite" to result.cipherSuite,
                "CA Verified" to if (result.isTrustedBySystemCa) "Trusted" else "Untrusted",
                "Certificates in Chain" to result.certificates.size.toString(),
                "Handshake Time" to "${result.handshakeLatencyMs}ms"
            )
        )
    }
}
