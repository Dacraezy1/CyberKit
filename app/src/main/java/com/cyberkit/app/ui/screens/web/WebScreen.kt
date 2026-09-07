package com.cyberkit.app.ui.screens.web

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
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
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.FindingCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader
import com.cyberkit.app.web.TlsAnalysisResult
import com.cyberkit.app.web.TlsAnalyzer
import com.cyberkit.app.web.UrlAnalysisResult
import com.cyberkit.app.web.UrlAnalyzer
import com.cyberkit.app.web.WebSecurityScanner
import kotlinx.coroutines.launch

@Composable
fun WebScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val db = remember { CyberKitDatabase.getDatabase(context) }

    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("URL Checker", "TLS Analyzer", "Web Assessment")

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
    ) {
        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = CyberSurfaceDark,
            contentColor = CyberCyan
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
                0 -> UrlCheckerTab(db)
                1 -> TlsAnalyzerTab(db)
                2 -> WebAssessmentTab(db)
            }
        }
    }
}

@Composable
fun UrlCheckerTab(db: CyberKitDatabase) {
    val coroutineScope = rememberCoroutineScope()
    var urlInput by remember { mutableStateOf("https://example.com") }
    var isLoading by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<UrlAnalysisResult?>(null) }
    var summary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "URL Security Checker",
            subtitle = "Syntax, HTTP headers, CSP, HSTS & cookie security",
            icon = Icons.Default.Language
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = urlInput,
                onValueChange = { urlInput = it },
                label = { Text("Target URL (e.g. https://example.com)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    isLoading = true
                    coroutineScope.launch {
                        val analyzer = UrlAnalyzer()
                        val res = analyzer.analyzeUrl(urlInput)
                        result = res
                        val s = analyzer.generateAssessmentSummary(res)
                        summary = s
                        db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(s))
                        isLoading = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
                Text(if (isLoading) "Evaluating Endpoint..." else "Analyze URL & Headers")
            }
        }

        summary?.let { s ->
            CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberGreen) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("URL SECURITY SCORE", fontSize = 12.sp, color = CyberGreen, fontFamily = FontFamily.Monospace)
                        Text(s.target, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    }
                    ScoreBadge(score = s.score)
                }
            }
        }

        result?.let { res ->
            // Headers Audit Grid
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                Text("SECURITY HEADERS AUDIT", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                Spacer(modifier = Modifier.height(8.dp))
                for ((header, present) in res.securityHeaders) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(header, fontSize = 13.sp, color = TextPrimaryDark)
                        Text(
                            text = if (present) "PRESENT" else "MISSING",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (present) CyberGreen else SeverityCritical,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        summary?.findings?.let { findings ->
            Text("FINDINGS (${findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in findings) {
                FindingCard(finding = f)
            }
        }
    }
}

@Composable
fun TlsAnalyzerTab(db: CyberKitDatabase) {
    val coroutineScope = rememberCoroutineScope()
    var hostInput by remember { mutableStateOf("google.com") }
    var portInput by remember { mutableStateOf("443") }
    var isLoading by remember { mutableStateOf(false) }
    var tlsResult by remember { mutableStateOf<TlsAnalysisResult?>(null) }
    var summary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "TLS Certificate & Cipher Analyzer",
            subtitle = "Certificate validity, issuer, SANs, key size & cipher suites",
            icon = Icons.Default.Https
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = hostInput,
                    onValueChange = { hostInput = it },
                    label = { Text("Host") },
                    modifier = Modifier.weight(3f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = portInput,
                    onValueChange = { portInput = it },
                    label = { Text("Port") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    isLoading = true
                    coroutineScope.launch {
                        val analyzer = TlsAnalyzer()
                        val p = portInput.toIntOrNull() ?: 443
                        val res = analyzer.analyzeTls(hostInput, p)
                        tlsResult = res
                        val s = analyzer.generateAssessmentSummary(res)
                        summary = s
                        db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(s))
                        isLoading = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
                Text(if (isLoading) "Performing TLS Handshake..." else "Inspect TLS Certificate")
            }
        }

        tlsResult?.let { res ->
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                Text("TLS PROTOCOL & CIPHER", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                Spacer(modifier = Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Protocol", color = TextSecondaryDark)
                    Text(res.protocol, fontWeight = FontWeight.Bold, color = CyberGreen)
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Cipher Suite", color = TextSecondaryDark)
                    Text(res.cipherSuite, fontWeight = FontWeight.SemiBold, fontSize = 12.sp, color = TextPrimaryDark)
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Handshake Latency", color = TextSecondaryDark)
                    Text("${res.handshakeLatencyMs}ms", color = CyberCyan)
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("System CA Trust", color = TextSecondaryDark)
                    Text(if (res.isTrustedBySystemCa) "Trusted" else "Untrusted", fontWeight = FontWeight.Bold, color = if (res.isTrustedBySystemCa) CyberGreen else SeverityCritical)
                }
            }

            val cert = res.certificates.firstOrNull()
            if (cert != null) {
                CyberCard(modifier = Modifier.fillMaxWidth()) {
                    Text("LEAF CERTIFICATE", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text("Subject: ${cert.subject}", fontSize = 12.sp, color = TextPrimaryDark)
                    Text("Issuer: ${cert.issuer}", fontSize = 12.sp, color = TextSecondaryDark)
                    Text("Expires: ${cert.validTo} (${cert.daysRemaining} days left)", fontSize = 12.sp, color = if (cert.daysRemaining < 30) SeverityHigh else CyberGreen)
                    Text("Signature: ${cert.signatureAlgorithm}", fontSize = 12.sp, color = TextMutedDark)
                    Text("Public Key: ${cert.publicKeyAlgorithm} ${if (cert.keySizeBits > 0) "${cert.keySizeBits} bits" else ""}", fontSize = 12.sp, color = TextMutedDark)
                }
            }
        }

        summary?.findings?.let { findings ->
            Text("TLS FINDINGS (${findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in findings) {
                FindingCard(finding = f)
            }
        }
    }
}

@Composable
fun WebAssessmentTab(db: CyberKitDatabase) {
    val coroutineScope = rememberCoroutineScope()
    var targetUrl by remember { mutableStateOf("https://example.com") }
    var isAuditing by remember { mutableStateOf(false) }
    var summary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Web Security Assessment",
            subtitle = "Non-destructive configuration, CORS & redirect checks",
            icon = Icons.Default.Security
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = targetUrl,
                onValueChange = { targetUrl = it },
                label = { Text("Target URL") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    isAuditing = true
                    coroutineScope.launch {
                        val scanner = WebSecurityScanner()
                        val s = scanner.auditWebTarget(targetUrl)
                        summary = s
                        db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(s))
                        isAuditing = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
                Text(if (isAuditing) "Evaluating Target..." else "Run Web Security Assessment")
            }
        }

        summary?.let { s ->
            CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberGreen) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("WEB CONFIGURATION SCORE", fontSize = 12.sp, color = CyberGreen, fontFamily = FontFamily.Monospace)
                        Text(s.target, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    }
                    ScoreBadge(score = s.score)
                }
            }

            Text("WEB FINDINGS (${s.findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in s.findings) {
                FindingCard(finding = f)
            }
        }
    }
}
