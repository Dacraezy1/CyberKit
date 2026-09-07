package com.cyberkit.app.smartaudit

import android.content.Context
import com.cyberkit.app.apk.ApkAnalyzer
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.device.DeviceAuditor
import com.cyberkit.app.device.InstalledAppAnalyzer
import com.cyberkit.app.files.FileSecurityAnalyzer
import com.cyberkit.app.network.DnsToolkit
import com.cyberkit.app.network.HostDiscovery
import com.cyberkit.app.network.NetworkUtils
import com.cyberkit.app.network.PortPresets
import com.cyberkit.app.network.PortScanner
import com.cyberkit.app.network.WifiAnalyzer
import com.cyberkit.app.web.TlsAnalyzer
import com.cyberkit.app.web.UrlAnalyzer
import com.cyberkit.app.web.WebSecurityScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

enum class AuditTargetType(val displayName: String, val description: String) {
    DEVICE("My Device", "Audits OS patch, lock screen, developer options, and installed application permissions"),
    WIFI("My Wi-Fi", "Audits active Wi-Fi encryption, signal, gateway security, and DNS configurations"),
    LOCAL_NETWORK("My Local Network", "Discovers active network hosts, evaluates exposed ports, and analyzes network posture"),
    WEBSITE("My Website", "Performs non-destructive web security, TLS certificate, and HTTP header audits"),
    APK("My APK", "Deconstructs APK manifest, exported components, permissions, and cryptographic signatures"),
    FILES("My Files", "Scans user-selected files for secrets, high entropy, archive traversal, and executable markers")
}

class SmartAuditCoordinator(private val context: Context) {

    suspend fun runDeviceAudit(
        onStep: (String) -> Unit
    ): AssessmentSummary = withContext(Dispatchers.IO) {
        onStep("Auditing Android OS security posture...")
        val auditor = DeviceAuditor(context)
        val posture = auditor.auditDevice()
        val deviceSummary = auditor.generateAssessmentSummary(posture)

        onStep("Auditing installed application permissions...")
        val appAnalyzer = InstalledAppAnalyzer(context)
        val apps = appAnalyzer.getInstalledApps(includeSystem = false)
        val appSummary = appAnalyzer.generateAssessmentSummary(apps)

        val combinedFindings = (deviceSummary.findings + appSummary.findings).distinctBy { it.title }
        val score = AssessmentSummary.calculateScore(combinedFindings)

        val metadata = HashMap<String, String>()
        metadata.putAll(deviceSummary.metadata)
        metadata.putAll(appSummary.metadata)

        AssessmentSummary(
            title = "Smart Audit: Local Device Posture",
            target = deviceSummary.target,
            module = "Smart Audit (Device)",
            score = score,
            findings = combinedFindings,
            metadata = metadata
        )
    }

    suspend fun runWifiAudit(
        onStep: (String) -> Unit
    ): AssessmentSummary = withContext(Dispatchers.IO) {
        onStep("Querying Wi-Fi interface details...")
        val wifiAnalyzer = WifiAnalyzer(context)
        val details = wifiAnalyzer.getWifiDetails()
        val wifiSummary = wifiAnalyzer.generateAssessmentSummary(details)

        val findings = wifiSummary.findings.toMutableList()

        if (details.isConnected && details.gateway != "Unavailable") {
            onStep("Checking gateway reachability & latency...")
            val latency = NetworkUtils.measureTcpLatency(details.gateway, 80, 1000)
            val metadata = HashMap(wifiSummary.metadata)
            metadata["Gateway Latency"] = if (latency >= 0) "${latency}ms" else "Filtered/ICMP Only"

            if (details.dnsServers.isNotEmpty()) {
                onStep("Evaluating DNS latency...")
                val dnsLatency = NetworkUtils.measureTcpLatency(details.dnsServers.first(), 53, 1000)
                metadata["Primary DNS Latency"] = if (dnsLatency >= 0) "${dnsLatency}ms" else "UDP Only"
            }

            AssessmentSummary(
                title = "Smart Audit: Wi-Fi (${details.ssid})",
                target = details.ssid,
                module = "Smart Audit (Wi-Fi)",
                score = AssessmentSummary.calculateScore(findings),
                findings = findings,
                metadata = metadata
            )
        } else {
            wifiSummary
        }
    }

    suspend fun runLocalNetworkAudit(
        subnetCidr: String,
        onStep: (String) -> Unit
    ): AssessmentSummary = withContext(Dispatchers.IO) {
        onStep("Calculating subnet configuration...")
        val subnet = NetworkUtils.calculateSubnet(subnetCidr)

        onStep("Discovering responsive hosts on ${subnet.cidrNotation}...")
        val discovery = HostDiscovery()
        val discoveredHosts = discovery.discoverSubnet(subnet.cidrNotation, timeoutMs = 800, concurrency = 25) { _, _, _ -> }
        val discoverySummary = discovery.generateAssessmentSummary(subnet.cidrNotation, discoveredHosts)

        val findings = discoverySummary.findings.toMutableList()

        // Scan top ports on discovered hosts (up to 3 hosts to prevent network congestion)
        val portScanner = PortScanner()
        val scannedHosts = discoveredHosts.take(3)
        for (h in scannedHosts) {
            onStep("Checking essential services on ${h.ip}...")
            val portResults = portScanner.scanPorts(h.ip, PortPresets.TOP_20.take(10), timeoutMs = 800, concurrency = 10) { _, _, _ -> }
            val portSummary = portScanner.generateAssessmentSummary(h.ip, portResults)
            findings.addAll(portSummary.findings)
        }

        val distinctFindings = findings.distinctBy { it.title + it.target }
        val score = AssessmentSummary.calculateScore(distinctFindings)

        AssessmentSummary(
            title = "Smart Audit: Local Network (${subnet.cidrNotation})",
            target = subnet.cidrNotation,
            module = "Smart Audit (Network)",
            score = score,
            findings = distinctFindings,
            metadata = mapOf(
                "Subnet" to subnet.cidrNotation,
                "Hosts Discovered" to discoveredHosts.size.toString(),
                "Hosts Scanned" to scannedHosts.size.toString()
            )
        )
    }

    suspend fun runWebsiteAudit(
        url: String,
        onStep: (String) -> Unit
    ): AssessmentSummary = withContext(Dispatchers.IO) {
        onStep("Auditing URL syntax and HTTP response headers...")
        val urlAnalyzer = UrlAnalyzer()
        val urlResult = urlAnalyzer.analyzeUrl(url)
        val urlSummary = urlAnalyzer.generateAssessmentSummary(urlResult)

        onStep("Analyzing TLS certificate chain & cipher negotiation...")
        val tlsAnalyzer = TlsAnalyzer()
        val host = urlResult.syntax.host
        val port = urlResult.syntax.port
        val tlsSummary = try {
            val tlsResult = tlsAnalyzer.analyzeTls(host, if (port == 80) 443 else port)
            tlsAnalyzer.generateAssessmentSummary(tlsResult)
        } catch (_: Exception) {
            null
        }

        onStep("Evaluating non-destructive web security configurations...")
        val webScanner = WebSecurityScanner()
        val webSummary = webScanner.auditWebTarget(url)

        val allFindings = mutableListOf<Finding>()
        allFindings.addAll(urlSummary.findings)
        tlsSummary?.let { allFindings.addAll(it.findings) }
        allFindings.addAll(webSummary.findings)

        val distinctFindings = allFindings.distinctBy { it.title }
        val score = AssessmentSummary.calculateScore(distinctFindings)

        AssessmentSummary(
            title = "Smart Audit: $host",
            target = url,
            module = "Smart Audit (Web)",
            score = score,
            findings = distinctFindings,
            metadata = mapOf(
                "Target" to host,
                "Final Status" to urlResult.finalStatusCode.toString(),
                "TLS Verified" to (tlsSummary?.metadata?.get("CA Verified") ?: "N/A"),
                "Redirects" to urlResult.redirects.size.toString()
            )
        )
    }

    suspend fun runApkAudit(
        apkFile: File,
        onStep: (String) -> Unit
    ): AssessmentSummary = withContext(Dispatchers.IO) {
        onStep("Parsing APK manifest and bytecode components...")
        val apkAnalyzer = ApkAnalyzer(context)
        val apkResult = apkAnalyzer.analyzeApkFile(apkFile)
        val summary = apkAnalyzer.generateAssessmentSummary(apkResult)
        summary
    }

    suspend fun runFileAudit(
        file: File,
        onStep: (String) -> Unit
    ): AssessmentSummary = withContext(Dispatchers.IO) {
        onStep("Evaluating Shannon entropy and format signatures...")
        val fileAnalyzer = FileSecurityAnalyzer()
        val fileResult = fileAnalyzer.analyzeFile(file)
        val summary = fileAnalyzer.generateAssessmentSummary(fileResult)
        summary
    }
}
