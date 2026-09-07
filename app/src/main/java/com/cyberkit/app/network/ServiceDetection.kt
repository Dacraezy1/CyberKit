package com.cyberkit.app.network

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class ServiceInfo(
    val port: Int,
    val serviceName: String,
    val banner: String = "",
    val confidence: String = "HIGH",
    val latencyMs: Long = 0L,
    val details: Map<String, String> = emptyMap()
)

object ServiceDetection {

    private val WELL_KNOWN_PORTS = mapOf(
        21 to "FTP",
        22 to "SSH",
        23 to "Telnet",
        25 to "SMTP",
        53 to "DNS",
        80 to "HTTP",
        110 to "POP3",
        143 to "IMAP",
        443 to "HTTPS",
        445 to "SMB",
        465 to "SMTPS",
        587 to "Submission",
        993 to "IMAPS",
        995 to "POP3S",
        1433 to "MSSQL",
        1521 to "Oracle DB",
        3306 to "MySQL",
        3389 to "RDP",
        5432 to "PostgreSQL",
        6379 to "Redis",
        8000 to "HTTP-Alt",
        8080 to "HTTP-Proxy/Alt",
        8443 to "HTTPS-Alt",
        9200 to "Elasticsearch",
        27017 to "MongoDB"
    )

    fun identifyPortName(port: Int): String = WELL_KNOWN_PORTS[port] ?: "Unknown"

    fun detectService(host: String, port: Int, timeoutMs: Int = 2000): ServiceInfo {
        val defaultName = identifyPortName(port)
        val startTime = System.currentTimeMillis()

        // 1. TLS/HTTPS inspection for port 443, 8443 or similar
        if (port == 443 || port == 8443 || port == 993 || port == 995 || port == 465) {
            try {
                val tlsInfo = inspectTlsService(host, port, timeoutMs)
                if (tlsInfo != null) {
                    return tlsInfo.copy(latencyMs = System.currentTimeMillis() - startTime)
                }
            } catch (_: Exception) {}
        }

        // 2. Banner grabbing for text protocols (SSH, FTP, SMTP)
        try {
            Socket().use { socket ->
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                val latency = System.currentTimeMillis() - startTime

                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                val writer = OutputStreamWriter(socket.getOutputStream())

                // For web ports, send safe HEAD request
                if (port == 80 || port == 8080 || port == 8000 || defaultName.startsWith("HTTP")) {
                    writer.write("HEAD / HTTP/1.1\r\nHost: $host\r\nUser-Agent: CyberKit-Recon/1.0\r\nConnection: close\r\n\r\n")
                    writer.flush()
                    val line = reader.readLine()
                    if (line != null && line.startsWith("HTTP/")) {
                        var serverBanner = line
                        var headerLine: String?
                        while (reader.readLine().also { headerLine = it } != null) {
                            if (headerLine!!.startsWith("Server:", ignoreCase = true)) {
                                serverBanner = headerLine!!.trim()
                                break
                            }
                        }
                        return ServiceInfo(
                            port = port,
                            serviceName = "HTTP",
                            banner = serverBanner,
                            confidence = "HIGH",
                            latencyMs = latency
                        )
                    }
                }

                // Passive banner read for SSH, FTP, SMTP
                val bannerLine = try {
                    reader.readLine()?.trim() ?: ""
                } catch (_: Exception) {
                    ""
                }

                if (bannerLine.isNotBlank()) {
                    val detectedName = when {
                        bannerLine.startsWith("SSH-", ignoreCase = true) -> "SSH"
                        bannerLine.startsWith("220", ignoreCase = true) && defaultName == "FTP" -> "FTP"
                        bannerLine.startsWith("220", ignoreCase = true) -> "SMTP"
                        else -> defaultName
                    }
                    return ServiceInfo(
                        port = port,
                        serviceName = detectedName,
                        banner = bannerLine.take(120),
                        confidence = "HIGH",
                        latencyMs = latency
                    )
                }

                return ServiceInfo(
                    port = port,
                    serviceName = defaultName,
                    banner = "Active response (no plain banner)",
                    confidence = if (defaultName != "Unknown") "MEDIUM" else "LOW",
                    latencyMs = latency
                )
            }
        } catch (_: Exception) {
            return ServiceInfo(
                port = port,
                serviceName = defaultName,
                banner = "Open port",
                confidence = "LOW",
                latencyMs = System.currentTimeMillis() - startTime
            )
        }
    }

    private fun inspectTlsService(host: String, port: Int, timeoutMs: Int): ServiceInfo? {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())

        (sslContext.socketFactory.createSocket() as SSLSocket).use { sslSocket ->
            sslSocket.soTimeout = timeoutMs
            sslSocket.connect(InetSocketAddress(host, port), timeoutMs)
            sslSocket.startHandshake()

            val session = sslSocket.session
            val peerCerts = session.peerCertificates
            val primaryCert = peerCerts.firstOrNull() as? X509Certificate
            val subject = primaryCert?.subjectX500Principal?.name ?: "Unknown Subject"

            return ServiceInfo(
                port = port,
                serviceName = if (port == 443 || port == 8443) "HTTPS" else "TLS/${identifyPortName(port)}",
                banner = "Protocol: ${session.protocol}, Cipher: ${session.cipherSuite}",
                confidence = "HIGH",
                details = mapOf(
                    "Protocol" to session.protocol,
                    "CipherSuite" to session.cipherSuite,
                    "Certificate Subject" to subject
                )
            )
        }
    }
}
