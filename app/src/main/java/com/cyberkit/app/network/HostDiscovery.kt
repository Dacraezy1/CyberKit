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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

data class DiscoveredHost(
    val ip: String,
    val hostname: String,
    val isReachable: Boolean,
    val latencyMs: Long,
    val detectionMethod: String,
    val respondingPorts: List<Int> = emptyList()
)

class HostDiscovery {

    suspend fun discoverSubnet(
        subnetCidr: String,
        timeoutMs: Int = 1000,
        concurrency: Int = 25,
        onProgress: (scanned: Int, total: Int, found: DiscoveredHost?) -> Unit
    ): List<DiscoveredHost> = withContext(Dispatchers.IO) {
        val subnet = NetworkUtils.calculateSubnet(subnetCidr)
        val ipList = generateHostIps(subnet)
        val semaphore = Semaphore(concurrency.coerceIn(1, 50))
        val discovered = mutableListOf<DiscoveredHost>()
        var scannedCount = 0
        val total = ipList.size

        coroutineScope {
            val jobs = ipList.map { ip ->
                async {
                    if (!isActive) return@async null
                    semaphore.withPermit {
                        if (!isActive) return@async null
                        val host = probeHost(ip, timeoutMs)
                        synchronized(discovered) {
                            scannedCount++
                            if (host != null) {
                                discovered.add(host)
                            }
                            onProgress(scannedCount, total, host)
                        }
                        host
                    }
                }
            }
            jobs.awaitAll()
        }

        discovered.sortedBy { NetworkUtils.ipToLong(it.ip) }
    }

    private fun generateHostIps(subnet: SubnetInfo): List<String> {
        val startLong = NetworkUtils.ipToLong(subnet.firstUsableHost)
        val endLong = NetworkUtils.ipToLong(subnet.lastUsableHost)
        // Cap to at most 254 hosts per scan for mobile battery and stability
        val count = ((endLong - startLong + 1).coerceIn(1, 254)).toInt()
        val list = ArrayList<String>(count)
        for (i in 0 until count) {
            list.add(NetworkUtils.longToIp(startLong + i))
        }
        return list
    }

    private fun probeHost(ip: String, timeoutMs: Int): DiscoveredHost? {
        val start = System.currentTimeMillis()

        // 1. Check reachability via InetAddress (ICMP / Echo)
        try {
            val inet = InetAddress.getByName(ip)
            if (inet.isReachable(timeoutMs)) {
                val latency = System.currentTimeMillis() - start
                val hostname = try { inet.canonicalHostName } catch (_: Exception) { ip }
                return DiscoveredHost(
                    ip = ip,
                    hostname = if (hostname == ip) "Unresolved" else hostname,
                    isReachable = true,
                    latencyMs = latency,
                    detectionMethod = "ICMP / OS Echo"
                )
            }
        } catch (_: Exception) {}

        // 2. TCP probe fallback (common ports 80, 443, 22, 53)
        val probePorts = listOf(80, 443, 22, 53)
        val responding = mutableListOf<Int>()
        var detected = false
        var probeLatency = 0L

        for (port in probePorts) {
            val pStart = System.currentTimeMillis()
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(ip, port), timeoutMs / 2)
                    detected = true
                    probeLatency = System.currentTimeMillis() - pStart
                    responding.add(port)
                }
            } catch (e: ConnectException) {
                // Connection refused means host is UP and sent a TCP RST packet!
                detected = true
                probeLatency = System.currentTimeMillis() - pStart
                break
            } catch (_: SocketTimeoutException) {
                // Host ignored or firewalled port
            } catch (_: Exception) {}
        }

        if (detected) {
            val hostname = try {
                val resolved = InetAddress.getByName(ip).canonicalHostName
                if (resolved == ip) "Unresolved" else resolved
            } catch (_: Exception) {
                "Unresolved"
            }
            return DiscoveredHost(
                ip = ip,
                hostname = hostname,
                isReachable = true,
                latencyMs = probeLatency,
                detectionMethod = "TCP Handshake / RST Response",
                respondingPorts = responding
            )
        }

        return null
    }

    fun generateAssessmentSummary(subnet: String, hosts: List<DiscoveredHost>): AssessmentSummary {
        val findings = mutableListOf<Finding>()

        findings.add(
            Finding(
                severity = FindingSeverity.INFO,
                title = "Host Discovery Completed on Subnet $subnet",
                description = "Discovered ${hosts.size} responsive host(s) on the specified authorized subnet.",
                evidence = "Active hosts: ${hosts.joinToString(", ") { "${it.ip} (${it.hostname})" }}",
                target = subnet,
                module = "Host Discovery",
                remediation = "Ensure all discovered hosts are known, authorized assets on your network inventory.",
                confidence = FindingConfidence.HIGH
            )
        )

        for (h in hosts) {
            if (h.respondingPorts.isNotEmpty()) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.INFO,
                        title = "Active Host ${h.ip} with Open Ports",
                        description = "Host ${h.ip} (${h.hostname}) responded on ports: ${h.respondingPorts.joinToString()}",
                        evidence = "Method: ${h.detectionMethod}, Latency: ${h.latencyMs}ms",
                        target = h.ip,
                        module = "Host Discovery",
                        remediation = "Conduct an authorized port assessment on this host to inventory exposed services.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }
        }

        return AssessmentSummary(
            title = "Subnet Discovery: $subnet",
            target = subnet,
            module = "Host Discovery",
            score = 100,
            findings = findings,
            metadata = mapOf(
                "Subnet" to subnet,
                "Active Hosts Count" to hosts.size.toString(),
                "Note" to "Android non-root apps rely on TCP fallback and unprivileged sockets due to OS sandbox."
            )
        )
    }
}
