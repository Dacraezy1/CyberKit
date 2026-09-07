package com.cyberkit.app.ui.screens.crypto

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.crypto.CryptoToolkit
import com.cyberkit.app.crypto.PasswordAnalyzer
import com.cyberkit.app.crypto.PasswordStrength
import com.cyberkit.app.cvss.CvssCalculator
import com.cyberkit.app.cvss.CvssMetrics
import com.cyberkit.app.cvss.CvssSeverity
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader

@Composable
fun CryptoScreen() {
    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Hashes & HMAC", "Encoders", "Password Analyzer", "CVSS Calculator")

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
    ) {
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
                0 -> HashTab()
                1 -> EncodersTab()
                2 -> PasswordTab()
                3 -> CvssTab()
            }
        }
    }
}

@Composable
fun HashTab() {
    var inputText by remember { mutableStateOf("CyberKit Security Assessment") }
    var hmacKey by remember { mutableStateOf("secret_key_123") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Cryptographic Hashes & HMAC",
            subtitle = "Compute deterministic one-way hash digests and HMAC signatures",
            icon = Icons.Default.Lock
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = inputText,
                onValueChange = { inputText = it },
                label = { Text("Input String / Data") },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = hmacKey,
                onValueChange = { hmacKey = it },
                label = { Text("HMAC Key") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            HashResultRow("MD5", CryptoToolkit.md5(inputText), isWeak = true)
            HashResultRow("SHA-1", CryptoToolkit.sha1(inputText), isWeak = true)
            HashResultRow("SHA-256", CryptoToolkit.sha256(inputText))
            HashResultRow("SHA-384", CryptoToolkit.sha384(inputText))
            HashResultRow("SHA-512", CryptoToolkit.sha512(inputText))
            HashResultRow("HMAC-SHA256", CryptoToolkit.hmacSha256(hmacKey, inputText))
            HashResultRow("HMAC-SHA512", CryptoToolkit.hmacSha512(hmacKey, inputText))
        }
    }
}

@Composable
private fun HashResultRow(algo: String, hash: String, isWeak: Boolean = false) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(algo, fontWeight = FontWeight.Bold, color = if (isWeak) SeverityHigh else CyberCyan, fontSize = 13.sp)
            if (isWeak) Text("(Legacy/Broken)", color = SeverityHigh, fontSize = 11.sp)
        }
        Text(hash, fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = TextPrimaryDark)
        Spacer(modifier = Modifier.height(4.dp))
        Divider(color = CyberCardBorder, thickness = 0.5.dp)
    }
}

@Composable
fun EncodersTab() {
    var rawText by remember { mutableStateOf("Cybersecurity Toolkit 2026") }
    var base64Text by remember { mutableStateOf("") }
    var hexText by remember { mutableStateOf("") }
    var urlEncodedText by remember { mutableStateOf("") }
    var generatedUuid by remember { mutableStateOf(CryptoToolkit.generateUuid()) }

    LaunchedEffect(rawText) {
        base64Text = CryptoToolkit.base64Encode(rawText)
        hexText = CryptoToolkit.stringToHex(rawText)
        urlEncodedText = CryptoToolkit.urlEncode(rawText)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Encoders, Decoders & Generators",
            subtitle = "Base64, Hexadecimal, URL, Binary & UUID v4",
            icon = Icons.Default.Transform
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = rawText,
                onValueChange = { rawText = it },
                label = { Text("Raw Plaintext") },
                modifier = Modifier.fillMaxWidth()
            )
        }

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Text("Base64 Encoded:", fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
            Text(base64Text, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            Spacer(modifier = Modifier.height(10.dp))

            Text("Hexadecimal:", fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
            Text(hexText, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            Spacer(modifier = Modifier.height(10.dp))

            Text("URL Encoded:", fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
            Text(urlEncodedText, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            Spacer(modifier = Modifier.height(10.dp))

            Text("Binary Stream:", fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
            Text(CryptoToolkit.stringToBinary(rawText.take(10)), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("Cryptographic UUID v4", fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.Bold)
                    Text(generatedUuid, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }
                IconButton(onClick = { generatedUuid = CryptoToolkit.generateUuid() }) {
                    Icon(Icons.Default.Refresh, contentDescription = "Regenerate", tint = CyberCyan)
                }
            }
        }
    }
}

@Composable
fun PasswordTab() {
    var passwordInput by remember { mutableStateOf("Tr0ub4dor&3_Secure!") }
    val result = remember(passwordInput) { PasswordAnalyzer.analyze(passwordInput) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Password Security Analyzer",
            subtitle = "100% offline entropy calculation & brute-force resistance",
            icon = Icons.Default.Password
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = passwordInput,
                onValueChange = { passwordInput = it },
                label = { Text("Password / Passphrase to Assess") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text("Evaluated locally in memory. Never saved or transmitted.", fontSize = 11.sp, color = CyberGreen)
        }

        CyberCard(
            modifier = Modifier.fillMaxWidth(),
            borderColor = when (result.strength) {
                PasswordStrength.VERY_STRONG -> CyberGreen
                PasswordStrength.STRONG -> CyberGreen.copy(alpha = 0.8f)
                PasswordStrength.FAIR -> CyberAmber
                PasswordStrength.WEAK -> SeverityCritical
            }
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("STRENGTH: ${result.strength}", fontWeight = FontWeight.Bold, fontSize = 16.sp, color = CyberCyan)
                    Text("Estimated Crack Time: ${result.estimatedCrackTime}", fontSize = 13.sp, color = TextSecondaryDark)
                }
                ScoreBadge(score = result.score)
            }

            Spacer(modifier = Modifier.height(12.dp))
            LinearProgressIndicator(
                progress = { result.score / 100f },
                modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                color = when (result.strength) {
                    PasswordStrength.VERY_STRONG -> CyberGreen
                    PasswordStrength.STRONG -> CyberCyan
                    PasswordStrength.FAIR -> CyberAmber
                    PasswordStrength.WEAK -> SeverityCritical
                }
            )

            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Entropy", color = TextSecondaryDark)
                Text("${String.format("%.1f", result.entropyBits)} bits", fontWeight = FontWeight.Bold, color = CyberCyan, fontFamily = FontFamily.Monospace)
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Length", color = TextSecondaryDark)
                Text("${result.length} chars", fontWeight = FontWeight.Bold, color = TextPrimaryDark)
            }
        }

        if (result.recommendations.isNotEmpty()) {
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                Text("RECOMMENDATIONS", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = CyberAmber)
                Spacer(modifier = Modifier.height(6.dp))
                for (rec in result.recommendations) {
                    Text("• $rec", fontSize = 12.sp, color = TextPrimaryDark, modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }
    }
}

@Composable
fun CvssTab() {
    var av by remember { mutableStateOf("N") }
    var ac by remember { mutableStateOf("L") }
    var pr by remember { mutableStateOf("N") }
    var ui by remember { mutableStateOf("N") }
    var s by remember { mutableStateOf("U") }
    var c by remember { mutableStateOf("H") }
    var i by remember { mutableStateOf("H") }
    var a by remember { mutableStateOf("H") }

    val cvssResult = remember(av, ac, pr, ui, s, c, i, a) {
        CvssCalculator.calculate(
            CvssMetrics(
                attackVector = av,
                attackComplexity = ac,
                privilegesRequired = pr,
                userInteraction = ui,
                scope = s,
                confidentiality = c,
                integrity = i,
                availability = a
            )
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "CVSS v3.1 Risk Calculator",
            subtitle = "Standardized vulnerability metrics and base score calculation",
            icon = Icons.Default.Calculate
        )

        CyberCard(
            modifier = Modifier.fillMaxWidth(),
            borderColor = when (cvssResult.severity) {
                CvssSeverity.CRITICAL -> SeverityCritical
                CvssSeverity.HIGH -> SeverityHigh
                CvssSeverity.MEDIUM -> SeverityMedium
                else -> CyberGreen
            }
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("CVSS v3.1 BASE SCORE", fontSize = 12.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
                    Text("${cvssResult.baseScore} / 10.0", fontSize = 24.sp, fontWeight = FontWeight.Black, color = when (cvssResult.severity) {
                        CvssSeverity.CRITICAL -> SeverityCritical
                        CvssSeverity.HIGH -> SeverityHigh
                        CvssSeverity.MEDIUM -> SeverityMedium
                        else -> CyberGreen
                    })
                }
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(when (cvssResult.severity) {
                            CvssSeverity.CRITICAL -> SeverityCritical
                            CvssSeverity.HIGH -> SeverityHigh
                            CvssSeverity.MEDIUM -> SeverityMedium
                            else -> CyberGreen
                        })
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = cvssResult.severity.name,
                        color = Color.Black,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Text(cvssResult.vectorString, fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = CyberCyan)
            Spacer(modifier = Modifier.height(6.dp))
            Text(cvssResult.explanation, fontSize = 12.sp, color = TextSecondaryDark)
        }

        // Metric Selectors
        MetricSelectorRow("Attack Vector (AV)", listOf("N" to "Network", "A" to "Adjacent", "L" to "Local", "P" to "Physical"), av) { av = it }
        MetricSelectorRow("Attack Complexity (AC)", listOf("L" to "Low", "H" to "High"), ac) { ac = it }
        MetricSelectorRow("Privileges Required (PR)", listOf("N" to "None", "L" to "Low", "H" to "High"), pr) { pr = it }
        MetricSelectorRow("User Interaction (UI)", listOf("N" to "None", "R" to "Required"), ui) { ui = it }
        MetricSelectorRow("Scope (S)", listOf("U" to "Unchanged", "C" to "Changed"), s) { s = it }
        MetricSelectorRow("Confidentiality (C)", listOf("N" to "None", "L" to "Low", "H" to "High"), c) { c = it }
        MetricSelectorRow("Integrity (I)", listOf("N" to "None", "L" to "Low", "H" to "High"), i) { i = it }
        MetricSelectorRow("Availability (A)", listOf("N" to "None", "L" to "Low", "H" to "High"), a) { a = it }
    }
}

@Composable
private fun MetricSelectorRow(
    title: String,
    options: List<Pair<String, String>>,
    selected: String,
    onSelect: (String) -> Unit
) {
    CyberCard(modifier = Modifier.fillMaxWidth()) {
        Text(title, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
        Spacer(modifier = Modifier.height(6.dp))
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            for ((key, label) in options) {
                FilterChip(
                    selected = selected == key,
                    onClick = { onSelect(key) },
                    label = { Text("$key: $label", fontSize = 12.sp) }
                )
            }
        }
    }
}
