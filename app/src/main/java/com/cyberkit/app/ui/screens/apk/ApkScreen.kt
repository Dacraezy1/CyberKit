package com.cyberkit.app.ui.screens.apk

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.apk.ApkAnalysisResult
import com.cyberkit.app.apk.ApkAnalyzer
import com.cyberkit.app.core.database.CyberKitDatabase
import com.cyberkit.app.core.database.ScanRecordEntity
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.files.FileAssessmentResult
import com.cyberkit.app.files.FileSecurityAnalyzer
import com.cyberkit.app.files.SecretMatch
import com.cyberkit.app.files.SecretScanner
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.FindingCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

@Composable
fun ApkScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val db = remember { CyberKitDatabase.getDatabase(context) }

    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("APK Analyzer", "File Security", "Secret Scanner", "Hash Verify")

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
                0 -> ApkAnalyzerTab(db)
                1 -> FileSecurityTab(db)
                2 -> SecretScannerTab(db)
                3 -> HashVerificationTab()
            }
        }
    }
}

@Composable
fun ApkAnalyzerTab(db: CyberKitDatabase) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var isAnalyzing by remember { mutableStateOf(false) }
    var apkResult by remember { mutableStateOf<ApkAnalysisResult?>(null) }
    var summary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            isAnalyzing = true
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val tempFile = File(context.cacheDir, "temp_target.apk")
                    context.contentResolver.openInputStream(uri)?.use { inStream ->
                        FileOutputStream(tempFile).use { outStream ->
                            inStream.copyTo(outStream)
                        }
                    }
                    val analyzer = ApkAnalyzer(context)
                    val res = analyzer.analyzeApkFile(tempFile)
                    val s = analyzer.generateAssessmentSummary(res)
                    apkResult = res
                    summary = s
                    db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(s))
                } catch (_: Exception) {}
                isAnalyzing = false
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Local APK Security Analyzer",
            subtitle = "Manifest inspection, exported components, permissions & bytecode audit",
            icon = Icons.Default.Android
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Text("Select an Android APK file to perform completely local offline static security analysis.", fontSize = 13.sp, color = TextSecondaryDark)
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = { launcher.launch("*/*") },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
                Icon(imageVector = Icons.Default.FolderOpen, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (isAnalyzing) "Deconstructing APK..." else "Select APK File")
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
                        Text("APK SECURITY SCORE", fontSize = 12.sp, color = CyberGreen, fontFamily = FontFamily.Monospace)
                        Text(apkResult?.packageName ?: s.target, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    }
                    ScoreBadge(score = s.score)
                }
            }
        }

        apkResult?.let { apk ->
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                Text("APK METADATA", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                Spacer(modifier = Modifier.height(6.dp))
                Text("Package: ${apk.packageName}", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                Text("Version: ${apk.versionName} (Code ${apk.versionCode})", fontSize = 12.sp, color = TextSecondaryDark)
                Text("SDK: min=${apk.minSdkVersion}, target=${apk.targetSdkVersion}", fontSize = 12.sp, color = TextSecondaryDark)
                Text("Debuggable: ${apk.isDebuggable}", fontSize = 12.sp, color = if (apk.isDebuggable) SeverityCritical else CyberGreen)
                Text("Allow Backup: ${apk.allowBackup}", fontSize = 12.sp, color = if (apk.allowBackup) CyberAmber else CyberGreen)
                Text("Cleartext Traffic: ${apk.usesCleartextTraffic}", fontSize = 12.sp, color = if (apk.usesCleartextTraffic) SeverityCritical else CyberGreen)
                Text("SHA-256: ${apk.hashes.sha256}", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextMutedDark)
            }

            if (apk.dangerousPermissions.isNotEmpty()) {
                CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberAmber.copy(alpha = 0.5f)) {
                    Text("DANGEROUS PERMISSIONS (${apk.dangerousPermissions.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = CyberAmber)
                    Spacer(modifier = Modifier.height(6.dp))
                    for (perm in apk.dangerousPermissions) {
                        Text(perm.removePrefix("android.permission."), fontSize = 12.sp, color = TextPrimaryDark)
                    }
                }
            }
        }

        summary?.findings?.let { findings ->
            Text("STATIC FINDINGS (${findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in findings) {
                FindingCard(finding = f)
            }
        }
    }
}

@Composable
fun FileSecurityTab(db: CyberKitDatabase) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var isAnalyzing by remember { mutableStateOf(false) }
    var fileResult by remember { mutableStateOf<FileAssessmentResult?>(null) }
    var summary by remember { mutableStateOf<com.cyberkit.app.core.model.AssessmentSummary?>(null) }

    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            isAnalyzing = true
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val tempFile = File(context.cacheDir, "temp_file_inspect")
                    context.contentResolver.openInputStream(uri)?.use { inStream ->
                        FileOutputStream(tempFile).use { outStream ->
                            inStream.copyTo(outStream)
                        }
                    }
                    val analyzer = FileSecurityAnalyzer()
                    val res = analyzer.analyzeFile(tempFile)
                    val s = analyzer.generateAssessmentSummary(res)
                    fileResult = res
                    summary = s
                    db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(s))
                } catch (_: Exception) {}
                isAnalyzing = false
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "File Security & Heuristic Analyzer",
            subtitle = "MIME types, Shannon entropy, executable magic bytes & archives",
            icon = Icons.Default.InsertDriveFile
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Text("Select any local file to inspect entropy, signatures, and archive safety.", fontSize = 13.sp, color = TextSecondaryDark)
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = { launcher.launch("*/*") },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
                Text(if (isAnalyzing) "Analyzing File..." else "Choose File to Audit")
            }
        }

        fileResult?.let { res ->
            CyberCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("ASSESSMENT RESULT", fontWeight = FontWeight.Bold, color = CyberCyan)
                    Text(res.riskCategory, fontWeight = FontWeight.Bold, color = if (res.riskCategory.contains("High")) SeverityCritical else CyberGreen)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text("MIME Type: ${res.mimeType}", fontSize = 13.sp)
                Text("Size: ${res.fileSize / 1024} KB", fontSize = 13.sp)
                Text("Entropy: ${String.format("%.2f", res.entropy)} / 8.0 bits", fontSize = 13.sp, color = CyberCyan)
                Text("SHA-256: ${res.sha256}", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextMutedDark)
            }
        }

        summary?.findings?.let { findings ->
            Text("HEURISTIC FINDINGS (${findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in findings) {
                FindingCard(finding = f)
            }
        }
    }
}

@Composable
fun SecretScannerTab(db: CyberKitDatabase) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var isScanning by remember { mutableStateOf(false) }
    var secrets by remember { mutableStateOf<List<SecretMatch>>(emptyList()) }

    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            isScanning = true
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val tempFile = File(context.cacheDir, "secret_inspect.txt")
                    context.contentResolver.openInputStream(uri)?.use { inStream ->
                        FileOutputStream(tempFile).use { outStream ->
                            inStream.copyTo(outStream)
                        }
                    }
                    secrets = SecretScanner.scanTextFile(tempFile)
                } catch (_: Exception) {}
                isScanning = false
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Credential & Secret Scanner",
            subtitle = "Local offline regex scanner for API keys, tokens & credentials",
            icon = Icons.Default.Key
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Text("Scan source code, JSON, properties, or configuration files for hardcoded secrets.", fontSize = 13.sp, color = TextSecondaryDark)
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = { launcher.launch("*/*") },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = Color.Black)
            ) {
                Text(if (isScanning) "Scanning Tokens..." else "Pick Configuration / Source File")
            }
        }

        if (secrets.isNotEmpty()) {
            Text("MATCHED SECRETS (${secrets.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = SeverityCritical)
            for (s in secrets) {
                CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = SeverityCritical.copy(alpha = 0.5f)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(s.ruleName, fontWeight = FontWeight.Bold, color = SeverityCritical)
                        Text("Line ${s.lineNumber}", color = CyberCyan, fontFamily = FontFamily.Monospace)
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(s.description, fontSize = 13.sp, color = TextSecondaryDark)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text("Snippet: ${s.maskedSnippet}", fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = TextPrimaryDark)
                }
            }
        }
    }
}

@Composable
fun HashVerificationTab() {
    var computedHash by remember { mutableStateOf("") }
    var expectedHash by remember { mutableStateOf("") }
    val isMatch = remember(computedHash, expectedHash) {
        computedHash.isNotBlank() && expectedHash.isNotBlank() && computedHash.trim().equals(expectedHash.trim(), ignoreCase = true)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Hash Verification Utility",
            subtitle = "Compare calculated file checksums against authentic hashes",
            icon = Icons.Default.Fingerprint
        )

        CyberCard(modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = computedHash,
                onValueChange = { computedHash = it },
                label = { Text("Calculated Hash (SHA-256 / MD5)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedTextField(
                value = expectedHash,
                onValueChange = { expectedHash = it },
                label = { Text("Expected Hash") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            if (computedHash.isNotBlank() && expectedHash.isNotBlank()) {
                Spacer(modifier = Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Comparison Result:", fontWeight = FontWeight.Bold)
                    Text(
                        text = if (isMatch) "HASHES MATCH (AUTHENTIC)" else "MISMATCH DETECTED (INTEGRITY FAILED)",
                        fontWeight = FontWeight.Bold,
                        color = if (isMatch) CyberGreen else SeverityCritical,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }
    }
}
