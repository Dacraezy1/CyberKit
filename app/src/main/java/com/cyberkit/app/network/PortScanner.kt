package com.cyberkit.app.network

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

enum class PortStatus {
    OPEN,
    CLOSED,
    FILTERED
}

data class PortScanResult(
    val port: Int,
    val status: PortStatus,
    val latencyMs: Long,
    val serviceInfo: ServiceInfo? = null
)

object PortPresets {
    val TOP_20 = listOf(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080)
    val WEB = listOf(80, 443, 8000, 8008, 8080, 8443, 8888, 9000, 9090, 9443)
    val DATABASE = listOf(1433, 1521, 3306, 5432, 6379, 27017, 9200, 11211)
    val ADMIN = listOf(21, 22, 23, 25, 53, 135, 139, 445, 3389, 5900)
    val PRIVILEGED_1024 = (1..1024).toList()
}

class PortScanner {

    suspend fun scanPorts(
        target: String,
        ports: List<Int>,
        timeoutMs: Int = 1200,
        concurrency: Int = 30,
        onProgress: (scanned: Int, total: Int, latest: PortScanResult?) -> Unit
    ): List<PortScanResult> = withContext(Dispatchers.IO) {
        val semaphore = Semaphore(concurrency.coerceIn(1, 100))
        val results = mutableListOf<PortScanResult>()
        var scannedCount = 0
        val total = ports.size

        coroutineScope {
            val deferreds = ports.map { port ->
                async {
                    if (!isActive) return@async null
                    semaphore.withPermit {
                        if (!isActive) return@async null
                        val result = checkPort(target, port, timeoutMs)
                        val detailedResult = if (result.status == PortStatus.OPEN) {
                            val svc = ServiceDetection.detectService(target, port, timeoutMs)
                            result.copy(serviceInfo = svc)
                        } else {
                            result
                        }
                        synchronized(results) {
                            scannedCount++
                            results.add(detailedResult)
                            onProgress(scannedCount, total, detailedResult)
                        }
                        detailedResult
                    }
                }
            }
            deferreds.awaitAll()
        }

        results.sortedBy { it.port }
    }

    private fun checkPort(host: String, port: Int, timeoutMs: Int): PortScanResult {
        val start = System.currentTimeMillis()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                PortScanResult(
                    port = port,
                    status = PortStatus.OPEN,
                    latencyMs = System.currentTimeMillis() - start
                )
            }
        } catch (e: SocketTimeoutException) {
            PortScanResult(
                port = port,
                status = PortStatus.FILTERED,
                latencyMs = timeoutMs.toLong()
            )
        } catch (e: ConnectException) {
            PortScanResult(
                port = port,
                status = PortStatus.CLOSED,
                latencyMs = System.currentTimeMillis() - start
            )
        } catch (e: Exception) {
            PortScanResult(
                port = port,
                status = PortStatus.FILTERED,
                latencyMs = System.currentTimeMillis() - start
            )
        }
    }

    fun generateAssessmentSummary(target: String, results: List<PortScanResult>): AssessmentSummary {
        val openPorts = results.filter { it.status == PortStatus.OPEN }
        val findings = mutableListOf<Finding>()

        for (open in openPorts) {
            val svc = open.serviceInfo
            when (open.port) {
                23 -> findings.add(
                    Finding(
                        severity = FindingSeverity.HIGH,
                        title = "Unencrypted Telnet Service Exposed (Port 23)",
                        description = "Telnet transmits authentication credentials and all communication in unencrypted plain text.",
                        evidence = "Port 23 is OPEN on $target. Banner: ${svc?.banner ?: "None"}",
                        target = "$target:23",
                        module = "Port Scanner",
                        remediation = "Disable Telnet and transition to SSH (port 22) with public key authentication.",
                        confidence = FindingConfidence.HIGH
                    )
                )
                21 -> findings.add(
                    Finding(
                        severity = FindingSeverity.MEDIUM,
                        title = "Plain FTP Service Exposed (Port 21)",
                        description = "Standard FTP transmits credentials and files in clear text unless configured with FTPS.",
                        evidence = "Port 21 is OPEN on $target. Banner: ${svc?.banner ?: "None"}",
                        target = "$target:21",
                        module = "Port Scanner",
                        remediation = "Migrate to SFTP (SSH File Transfer Protocol) or enforce FTPS (TLS).",
                        confidence = FindingConfidence.HIGH
                    )
                )
                3389 -> findings.add(
                    Finding(
                        severity = FindingSeverity.MEDIUM,
                        title = "Remote Desktop Protocol (RDP) Exposed (Port 3389)",
                        description = "Exposed RDP services are frequently targeted by brute-force attacks and automated credential scanners.",
                        evidence = "Port 3389 is OPEN on $target",
                        target = "$target:3389",
                        module = "Port Scanner",
                        remediation = "Restrict RDP access behind a VPN or firewall; enforce Network Level Authentication (NLA) and multi-factor authentication.",
                        confidence = FindingConfidence.HIGH
                    )
                )
                6379, 27017, 9200 -> findings.add(
                    Finding(
                        severity = FindingSeverity.HIGH,
                        title = "Database / Datastore Port Exposed (${open.port})",
                        description = "Internal database ports should not be accessible over public or untrusted network interfaces.",
                        evidence = "Port ${open.port} (${svc?.serviceName ?: "Database"}) is OPEN on $target",
                        target = "$target:${open.port}",
                        module = "Port Scanner",
                        remediation = "Bind database listeners to localhost (127.0.0.1) or restrict access via firewall rules.",
                        confidence = FindingConfidence.HIGH
                    )
                )
                80 -> findings.add(
                    Finding(
                        severity = FindingSeverity.LOW,
                        title = "Unencrypted HTTP Service (Port 80)",
                        description = "Port 80 is listening. Ensure all HTTP traffic redirects to HTTPS with HSTS enabled.",
                        evidence = "Port 80 is OPEN on $target",
                        target = "$target:80",
                        module = "Port Scanner",
                        remediation = "Enforce HTTPS (port 443) and issue an HTTP 301 redirect for all cleartext requests.",
                        confidence = FindingConfidence.HIGH
                    )
                )
                else -> {
                    findings.add(
                        Finding(
                            severity = FindingSeverity.INFO,
                            title = "Open TCP Service: ${svc?.serviceName ?: "Unknown"} (Port ${open.port})",
                            description = "Service detected listening on port ${open.port}. Verify this service is authorized.",
                            evidence = "Port ${open.port} OPEN, Banner: ${svc?.banner ?: "None"}, Latency: ${open.latencyMs}ms",
                            target = "$target:${open.port}",
                            module = "Port Scanner",
                            remediation = "Review open ports against security policies and shut down unnecessary listening services.",
                            confidence = FindingConfidence.HIGH
                        )
                    )
                }
            }
        }

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "TCP Port Scan: $target",
            target = target,
            module = "Port Scanner",
            score = score,
            findings = findings,
            metadata = mapOf(
                "Total Scanned" to results.size.toString(),
                "Open Ports" to openPorts.size.toString(),
                "Closed Ports" to results.count { it.status == PortStatus.CLOSED }.toString(),
                "Filtered Ports" to results.count { it.status == PortStatus.FILTERED }.toString()
            )
        )
    }
}
