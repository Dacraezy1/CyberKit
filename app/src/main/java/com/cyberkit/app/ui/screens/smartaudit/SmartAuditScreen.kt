package com.cyberkit.app.ui.screens.smartaudit

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.smartaudit.AuditTargetType
import com.cyberkit.app.smartaudit.SmartAuditCoordinator
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.FindingCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileOutputStream

@Composable
fun SmartAuditScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val db = remember { CyberKitDatabase.getDatabase(context) }
    val coordinator = remember { SmartAuditCoordinator(context) }

    var isRunning by remember { mutableStateOf(false) }
    var currentStep by remember { mutableStateOf("") }
    var auditResult by remember { mutableStateOf<AssessmentSummary?>(null) }

    var showNetworkDialog by remember { mutableStateOf(false) }
    var networkInput by remember { mutableStateOf("192.168.1.0/24") }

    var showWebDialog by remember { mutableStateOf(false) }
    var webInput by remember { mutableStateOf("https://example.com") }

    val apkLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri != null) {
            isRunning = true
            currentStep = "Loading APK..."
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val file = File(context.cacheDir, "smart_apk_target.apk")
                    context.contentResolver.openInputStream(uri)?.use { inStream ->
                        FileOutputStream(file).use { outStream -> inStream.copyTo(outStream) }
                    }
                    val res = coordinator.runApkAudit(file) { currentStep = it }
                    auditResult = res
                    db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(res))
                } catch (_: Exception) {}
                isRunning = false
            }
        }
    }

    val fileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri != null) {
            isRunning = true
            currentStep = "Loading file..."
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val file = File(context.cacheDir, "smart_file_target")
                    context.contentResolver.openInputStream(uri)?.use { inStream ->
                        FileOutputStream(file).use { outStream -> inStream.copyTo(outStream) }
                    }
                    val res = coordinator.runFileAudit(file) { currentStep = it }
                    auditResult = res
                    db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(res))
                } catch (_: Exception) {}
                isRunning = false
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Smart Security Audit",
            subtitle = "Automated multi-tool assessment pipeline for authorized assets",
            icon = Icons.Default.SecurityUpdateGood
        )

        // Target Selector Cards
        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Text("Select target asset to evaluate:", fontSize = 13.sp, color = TextSecondaryDark)
            Spacer(modifier = Modifier.height(10.dp))

            val targets = AuditTargetType.values()
            for (target in targets) {
                Button(
                    onClick = {
                        if (!isRunning) {
                            when (target) {
                                AuditTargetType.DEVICE -> {
                                    isRunning = true
                                    coroutineScope.launch {
                                        val res = coordinator.runDeviceAudit { currentStep = it }
                                        auditResult = res
                                        db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(res))
                                        isRunning = false
                                    }
                                }
                                AuditTargetType.WIFI -> {
                                    isRunning = true
                                    coroutineScope.launch {
                                        val res = coordinator.runWifiAudit { currentStep = it }
                                        auditResult = res
                                        db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(res))
                                        isRunning = false
                                    }
                                }
                                AuditTargetType.LOCAL_NETWORK -> showNetworkDialog = true
                                AuditTargetType.WEBSITE -> showWebDialog = true
                                AuditTargetType.APK -> apkLauncher.launch("*/*")
                                AuditTargetType.FILES -> fileLauncher.launch("*/*")
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CyberSurfaceDark,
                        contentColor = TextPrimaryDark
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(target.displayName, fontWeight = FontWeight.Bold, color = CyberCyan, fontSize = 14.sp)
                            Text(target.description, fontSize = 11.sp, color = TextSecondaryDark)
                        }
                        Icon(Icons.Default.PlayCircle, contentDescription = null, tint = CyberCyan)
                    }
                }
            }
        }

        if (isRunning) {
            CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberCyan) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(color = CyberCyan, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(currentStep, fontSize = 13.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
                }
            }
        }

        auditResult?.let { res ->
            CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberGreen) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(res.title, fontWeight = FontWeight.Bold, fontSize = 16.sp, color = TextPrimaryDark)
                        Text("Module: ${res.module}", fontSize = 12.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
                    }
                    ScoreBadge(score = res.score)
                }
            }

            Text("CONSOLIDATED FINDINGS (${res.findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
            for (f in res.findings) {
                FindingCard(finding = f)
            }
        }

        // Dialogs
        if (showNetworkDialog) {
            AlertDialog(
                onDismissRequest = { showNetworkDialog = false },
                title = { Text("Authorized Subnet Audit") },
                text = {
                    Column {
                        Text("Enter your authorized subnet range to assess:")
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = networkInput,
                            onValueChange = { networkInput = it },
                            label = { Text("Subnet (CIDR)") },
                            singleLine = true
                        )
                    }
                },
                confirmButton = {
                    Button(onClick = {
                        showNetworkDialog = false
                        isRunning = true
                        coroutineScope.launch {
                            val res = coordinator.runLocalNetworkAudit(networkInput) { currentStep = it }
                            auditResult = res
                            db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(res))
                            isRunning = false
                        }
                    }) { Text("Run Network Audit") }
                },
                dismissButton = {
                    TextButton(onClick = { showNetworkDialog = false }) { Text("Cancel") }
                }
            )
        }

        if (showWebDialog) {
            AlertDialog(
                onDismissRequest = { showWebDialog = false },
                title = { Text("Authorized Website Audit") },
                text = {
                    Column {
                        Text("Enter target domain or URL you are authorized to assess:")
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = webInput,
                            onValueChange = { webInput = it },
                            label = { Text("URL / Hostname") },
                            singleLine = true
                        )
                    }
                },
                confirmButton = {
                    Button(onClick = {
                        showWebDialog = false
                        isRunning = true
                        coroutineScope.launch {
                            val res = coordinator.runWebsiteAudit(webInput) { currentStep = it }
                            auditResult = res
                            db.scanDao().insertScan(ScanRecordEntity.fromAssessmentSummary(res))
                            isRunning = false
                        }
                    }) { Text("Run Web Audit") }
                },
                dismissButton = {
                    TextButton(onClick = { showWebDialog = false }) { Text("Cancel") }
                }
            )
        }
    }
}
