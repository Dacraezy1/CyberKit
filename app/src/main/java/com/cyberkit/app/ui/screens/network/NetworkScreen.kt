package com.cyberkit.app.ui.screens.network

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.core.database.CyberKitDatabase
import com.cyberkit.app.core.database.ScanRecordEntity
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.network.*
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.FindingCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

@Composable
fun NetworkScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val db = remember { CyberKitDatabase.getDatabase(context) }

    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Port Scanner", "Host Discovery", "CIDR Calculator", "Wi-Fi Analyzer", "DNS Toolkit", "Interfaces")

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
    ) {
        // Tab row
        ScrollableTabRow(
            selectedTabIndex = selectedTab,
            containerColor = CyberSurfaceDark,
            contentColor = CyberCyan,
            edgePadding = 16.dp
        ) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selectedTab == index,
                    onClick = { selectedTab = index },
                    text = { Text(title, fontWeight = if (selectedTab == index) FontWeight.Bold else FontWeight.Normal) }
                )
            }
        }

        Box(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            when (selectedTab) {
                0 -> PortScannerTab(db)
                1 -> HostDiscoveryTab(db)
                2 -> SubnetCalculatorTab()
                3 -> WifiAnalyzerTab(db)
                4 -> DnsToolkitTab(db)
                5 -> InterfacesTab()
            }
        }
    }
}

@Composable
fun PortScannerTab(db: CyberKitDatabase) {
    val coroutineScope = rememberCoroutineScope()
    var targetHost by remember { mutableStateOf("127.0.0.1") }
    var customPorts by remember { mutableStateOf("21, 22, 80, 443, 8080") }
    var selectedPreset by remember { mutableStateOf("Top 20") }
    var isScanning by remember { mutableStateOf(false) }
    var scanProgress by remember { mutableStateOf(0f) }
    var scanResults by remember { mutableStateOf<List<PortScanResult>>(emptyList()) }
    var scanJob by remember { mutableStateOf<Job?>(null) }
    var assessmentSummary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Authorized TCP Port Scanner",
            subtitle = "Safe TCP connect diagnostics with service identification",
            icon = Icons.Default.Radar
        )

        // Target and presets
        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = targetHost,
                onValueChange = { targetHost = it },
                label = { Text("Target Host / IP") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = CyberCyan,
                    unfocusedBorderColor = CyberCardBorder
                )
            )

            Spacer(modifier = Modifier.height(12.dp))
            Text("Port Presets:", fontSize = 12.sp, color = TextSecondaryDark)
            Spacer(modifier = Modifier.height(6.dp))

            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val presets = listOf("Top 20", "Web", "Admin", "Database", "1-1024", "Custom")
                for (p in presets) {
                    FilterChip(
                        selected = selectedPreset == p,
                        onClick = {
                            selectedPreset = p
                            when (p) {
                                "Top 20" -> customPorts = PortPresets.TOP_20.joinToString(", ")
                                "Web" -> customPorts = PortPresets.WEB.joinToString(", ")
                                "Admin" -> customPorts = PortPresets.ADMIN.joinToString(", ")
                                "Database" -> customPorts = PortPresets.DATABASE.joinToString(", ")
                                "1-1024" -> customPorts = "1-1024"
                            }
                        },
                        label = { Text(p, fontSize = 12.sp) }
                    )
                }
            }

            if (selectedPreset == "Custom" || selectedPreset == "1-1024") {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = customPorts,
                    onValueChange = { customPorts = it },
                    label = { Text("Ports (e.g. 80, 443 or 1-100)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = {
                        if (isScanning) {
                            scanJob?.cancel()
                            isScanning = false
                        } else {
                            val portsToScan = NetworkUtils.parsePortRange(customPorts)
                            if (portsToScan.isNotEmpty()) {
                                isScanning = true
                                scanProgress = 0f
                                scanResults = emptyList()
                                assessmentSummary = null

                                scanJob = coroutineScope.launch {
                                    val scanner = PortScanner()
                                    val results = scanner.scanPorts(
                                        target = targetHost,
                                        ports = portsToScan,
                                        timeoutMs = 1200,
                                        concurrency = 30
                                    ) { scanned, total, _ ->
                                        scanProgress = scanned.toFloat() / total.toFloat()
                                    }
                                    scanResults = results
                                    val summary = scanner.generateAssessmentSummary(targetHost, results)
                                    assessmentSummary = summary
                                    db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(summary))
                                    isScanning = false
                                }
                            }
                        }
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isScanning) SeverityCritical else CyberCyan,
                        contentColor = Color.Black
                    )
                ) {
                    Icon(
                        imageVector = if (isScanning) Icons.Default.Cancel else Icons.Default.PlayArrow,
                        contentDescription = null
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(if (isScanning) "Cancel Scan" else "Start TCP Scan")
                }
            }

            if (isScanning) {
                Spacer(modifier = Modifier.height(12.dp))
                LinearProgressIndicator(
                    progress = { scanProgress },
                    modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                    color = CyberCyan,
                    trackColor = CyberBgDark
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Scanning: ${(scanProgress * 100).toInt()}%",
                    fontSize = 11.sp,
                    color = CyberCyan,
                    fontFamily = FontFamily.Monospace
                )
            }
        }

        // Assessment Summary Card
        assessmentSummary?.let { summary ->
            CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberGreen) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("PORT SCAN ASSESSMENT", fontSize = 12.sp, color = CyberGreen, fontFamily = FontFamily.Monospace)
                        Text("${summary.target} - Score ${summary.score}/100", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    }
                    ScoreBadge(score = summary.score)
                }
            }
        }

        // Open Ports Table
        val openPorts = scanResults.filter { it.status == PortStatus.OPEN }
        if (openPorts.isNotEmpty()) {
            Text("OPEN PORTS (${openPorts.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = CyberGreen)
            for (p in openPorts) {
                CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberGreen.copy(alpha = 0.5f)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("PORT ${p.port}", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = CyberCyan, fontFamily = FontFamily.Monospace)
                        Text(p.serviceInfo?.serviceName ?: "Unknown", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimaryDark)
                        Text("${p.latencyMs}ms", fontSize = 12.sp, color = TextMutedDark, fontFamily = FontFamily.Monospace)
                    }
                    if (!p.serviceInfo?.banner.isNullOrBlank()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Text("Banner: ${p.serviceInfo?.banner}", fontSize = 12.sp, color = TextSecondaryDark, fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }

        // Findings
        assessmentSummary?.findings?.let { findings ->
            if (findings.isNotEmpty()) {
                Text("SECURITY FINDINGS (${findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = TextPrimaryDark)
                for (f in findings) {
                    FindingCard(finding = f)
                }
            }
        }
    }
}

@Composable
fun HostDiscoveryTab(db: CyberKitDatabase) {
    val coroutineScope = rememberCoroutineScope()
    var subnetInput by remember { mutableStateOf("192.168.1.0/24") }
    var isDiscovering by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0f) }
    var discoveredHosts by remember { mutableStateOf<List<DiscoveredHost>>(emptyList()) }
    var discoveryJob by remember { mutableStateOf<Job?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Subnet Host Discovery",
            subtitle = "ICMP & TCP fallback discovery for authorized subnets",
            icon = Icons.Default.Search
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = subnetInput,
                onValueChange = { subnetInput = it },
                label = { Text("Subnet CIDR (e.g. 192.168.1.0/24)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    if (isDiscovering) {
                        discoveryJob?.cancel()
                        isDiscovering = false
                    } else {
                        isDiscovering = true
                        progress = 0f
                        discoveredHosts = emptyList()

                        discoveryJob = coroutineScope.launch {
                            val discovery = HostDiscovery()
                            val hosts = discovery.discoverSubnet(
                                subnetCidr = subnetInput,
                                timeoutMs = 800,
                                concurrency = 25
                            ) { scanned, total, _ ->
                                progress = scanned.toFloat() / total.toFloat()
                            }
                            discoveredHosts = hosts
                            val summary = discovery.generateAssessmentSummary(subnetInput, hosts)
                            db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(summary))
                            isDiscovering = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isDiscovering) SeverityCritical else CyberCyan,
                    contentColor = Color.Black
                )
            ) {
                Text(if (isDiscovering) "Cancel Discovery" else "Discover Responsive Hosts")
            }

            if (isDiscovering) {
                Spacer(modifier = Modifier.height(12.dp))
                LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                    color = CyberCyan
                )
            }
        }

        if (discoveredHosts.isNotEmpty()) {
            Text("RESPONSIVE HOSTS (${discoveredHosts.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = CyberGreen)
            for (h in discoveredHosts) {
                CyberCard(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(h.ip, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = CyberCyan, fontFamily = FontFamily.Monospace)
                            Text(h.hostname, fontSize = 13.sp, color = TextSecondaryDark)
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Text("${h.latencyMs}ms", fontSize = 12.sp, color = CyberGreen, fontFamily = FontFamily.Monospace)
                            Text(h.detectionMethod, fontSize = 11.sp, color = TextMutedDark)
                        }
                    }
                    if (h.respondingPorts.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("Open TCP ports: ${h.respondingPorts.joinToString()}", fontSize = 12.sp, color = CyberAmber)
                    }
                }
            }
        }
    }
}

@Composable
fun SubnetCalculatorTab() {
    var cidrInput by remember { mutableStateOf("192.168.1.100/24") }
    val subnet = remember(cidrInput) {
        try {
            NetworkUtils.calculateSubnet(cidrInput)
        } catch (_: Exception) {
            null
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "CIDR & Subnet Calculator",
            subtitle = "Network boundaries, netmask, wildcard & host capacity",
            icon = Icons.Default.Calculate
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = cidrInput,
                onValueChange = { cidrInput = it },
                label = { Text("IP / Prefix (e.g. 10.0.0.1/20 or 192.168.1.1/24)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }

        if (subnet != null) {
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                SubnetRow("Network Address", subnet.networkAddress)
                SubnetRow("Broadcast Address", subnet.broadcastAddress)
                SubnetRow("Subnet Mask", subnet.netmask)
                SubnetRow("Wildcard Mask", subnet.wildcardMask)
                SubnetRow("First Usable Host", subnet.firstUsableHost)
                SubnetRow("Last Usable Host", subnet.lastUsableHost)
                SubnetRow("Usable Hosts Count", "${subnet.usableHosts} / ${subnet.totalHosts}")
                SubnetRow("Hexadecimal IP", NetworkUtils.ipToHex(subnet.ip))
                SubnetRow("Binary IP", NetworkUtils.ipToBinary(subnet.ip))
            }
        }
    }
}

@Composable
private fun SubnetRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 13.sp, color = TextSecondaryDark)
        Text(value, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextPrimaryDark, fontFamily = FontFamily.Monospace)
    }
}

@Composable
fun WifiAnalyzerTab(db: CyberKitDatabase) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var wifiDetails by remember { mutableStateOf(WifiAnalyzer(context).getWifiDetails()) }
    var summary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Wi-Fi Security Analyzer",
            subtitle = "Wireless channel, encryption type & gateway diagnostics",
            icon = Icons.Default.Wifi
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(wifiDetails.ssid, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                    Text("Security: ${wifiDetails.securityType}", fontSize = 13.sp, color = TextSecondaryDark)
                }
                Button(
                    onClick = {
                        val analyzer = WifiAnalyzer(context)
                        val details = analyzer.getWifiDetails()
                        wifiDetails = details
                        val s = analyzer.generateAssessmentSummary(details)
                        summary = s
                        coroutineScope.launch {
                            db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(s))
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
                ) {
                    Text("Audit Wi-Fi")
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            SubnetRow("Signal Strength", "${wifiDetails.signalPercent}% (${wifiDetails.rssi} dBm)")
            SubnetRow("Frequency & Band", "${wifiDetails.frequencyMhz} MHz (${wifiDetails.band})")
            SubnetRow("Channel", "${wifiDetails.channel}")
            SubnetRow("Link Speed", "${wifiDetails.linkSpeedMbps} Mbps")
            SubnetRow("Local IPv4", wifiDetails.ipAddress)
            SubnetRow("Gateway IP", wifiDetails.gateway)
            SubnetRow("DNS Servers", wifiDetails.dnsServers.joinToString(", ").ifEmpty { "None" })
        }

        summary?.findings?.let { findings ->
            Text("WIFI FINDINGS (${findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in findings) {
                FindingCard(finding = f)
            }
        }
    }
}

@Composable
fun DnsToolkitTab(db: CyberKitDatabase) {
    val coroutineScope = rememberCoroutineScope()
    var domainInput by remember { mutableStateOf("cloudflare.com") }
    var isLoading by remember { mutableStateOf(false) }
    var dnsResult by remember { mutableStateOf<DnsAnalysisResult?>(null) }
    var summary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "DNS Toolkit & Security Assessment",
            subtitle = "A, AAAA, MX, NS, TXT, DNSSEC & reverse resolution",
            icon = Icons.Default.Dns
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = domainInput,
                onValueChange = { domainInput = it },
                label = { Text("Domain (e.g. example.com)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    isLoading = true
                    coroutineScope.launch {
                        val toolkit = DnsToolkit()
                        val res = toolkit.analyzeDomain(domainInput)
                        dnsResult = res
                        val s = toolkit.generateAssessmentSummary(res)
                        summary = s
                        db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(s))
                        isLoading = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
                Text(if (isLoading) "Querying DNS..." else "Resolve DNS Records")
            }
        }

        dnsResult?.let { res ->
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("DNSSEC: ${if (res.dnssecValid) "Active (Verified)" else "Inactive"}", fontWeight = FontWeight.Bold, color = if (res.dnssecValid) CyberGreen else CyberAmber)
                    Text("Latency: ${res.latencyMs}ms", fontFamily = FontFamily.Monospace, color = CyberCyan)
                }
                Spacer(modifier = Modifier.height(8.dp))
                for (r in res.records) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(r.recordType, color = CyberCyan, fontWeight = FontWeight.Bold, modifier = Modifier.width(60.dp))
                        Text(r.value, color = TextPrimaryDark, modifier = Modifier.weight(1f), maxLines = 2)
                    }
                }
            }
        }

        summary?.findings?.let { findings ->
            Text("DNS FINDINGS (${findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in findings) {
                FindingCard(finding = f)
            }
        }
    }
}

@Composable
fun InterfacesTab() {
    val interfaces = remember { NetworkUtils.getAllNetworkInterfaces() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Network Interfaces",
            subtitle = "Active device network adapters, loopbacks & sockets",
            icon = Icons.Default.SettingsEthernet
        )

        for (intf in interfaces) {
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(intf.name, fontWeight = FontWeight.Bold, color = CyberCyan)
                    Text(if (intf.isUp) "UP" else "DOWN", color = if (intf.isUp) CyberGreen else TextMutedDark, fontWeight = FontWeight.Bold)
                }
                SubnetRow("Display Name", intf.displayName)
                SubnetRow("MTU", intf.mtu.toString())
                SubnetRow("Loopback", intf.isLoopback.toString())
                if (intf.ipv4Addresses.isNotEmpty()) {
                    SubnetRow("IPv4", intf.ipv4Addresses.joinToString())
                }
                if (intf.ipv6Addresses.isNotEmpty()) {
                    SubnetRow("IPv6", intf.ipv6Addresses.take(2).joinToString())
                }
            }
        }
    }
}
