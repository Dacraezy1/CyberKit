package com.cyberkit.app.ui.screens.device

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import com.cyberkit.app.core.database.CyberKitDatabase
import com.cyberkit.app.core.database.ScanRecordEntity
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.device.DeviceAuditor
import com.cyberkit.app.device.DeviceSecurityPosture
import com.cyberkit.app.device.InstalledAppAnalyzer
import com.cyberkit.app.device.InstalledAppInfo
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.FindingCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader
import kotlinx.coroutines.launch

@Composable
fun DeviceScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val db = remember { CyberKitDatabase.getDatabase(context) }

    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Device Posture", "Installed Apps")

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
                0 -> DevicePostureTab(db)
                1 -> InstalledAppsTab(db)
            }
        }
    }
}

@Composable
fun DevicePostureTab(db: CyberKitDatabase) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val auditor = remember { DeviceAuditor(context) }
    var posture by remember { mutableStateOf(auditor.auditDevice()) }
    var summary by remember { mutableStateOf(auditor.generateAssessmentSummary(posture)) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionHeader(
            title = "Android Device Security Audit",
            subtitle = "Evaluation of device configuration, patch level & lock security",
            icon = Icons.Default.Security
        )

        CyberCard(modifier = Modifier.fillMaxWidth(), borderColor = CyberGreen) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("DEVICE POSTURE SCORE", fontSize = 12.sp, color = CyberGreen, fontFamily = FontFamily.Monospace)
                    Text("Android ${posture.androidVersion} (API ${posture.sdkInt})", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                }
                ScoreBadge(score = summary.score)
            }

            Spacer(modifier = Modifier.height(12.dp))
            PostureItem("Screen Lock Security", if (posture.isDeviceSecure) "Active (PIN/Biometric)" else "None (Vulnerable)", posture.isDeviceSecure)
            PostureItem("Storage Encryption", if (posture.isStorageEncrypted) "Encrypted" else "Unencrypted", posture.isStorageEncrypted)
            PostureItem("Security Patch Date", posture.securityPatchDate, posture.patchAgeMonths <= 2)
            PostureItem("USB Debugging (ADB)", if (posture.isAdbEnabled) "Active (Risk)" else "Disabled (Safe)", !posture.isAdbEnabled)
            PostureItem("Developer Options", if (posture.isDeveloperOptionsEnabled) "Enabled" else "Disabled", !posture.isDeveloperOptionsEnabled)
            PostureItem("VPN Active", if (posture.isVpnActive) "Yes" else "No", true)
            PostureItem("Proxy Configured", if (posture.isProxyConfigured) "Yes" else "No", !posture.isProxyConfigured)
        }

        Text("DEVICE FINDINGS (${summary.findings.size})", fontSize = 14.sp, fontWeight = FontWeight.Bold)
        for (f in summary.findings) {
            FindingCard(finding = f)
        }
    }
}

@Composable
private fun PostureItem(label: String, value: String, isGood: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 13.sp, color = TextSecondaryDark)
        Text(
            text = value,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (isGood) CyberGreen else SeverityCritical
        )
    }
}

@Composable
fun InstalledAppsTab(db: CyberKitDatabase) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var appList by remember { mutableStateOf<List<InstalledAppInfo>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        isLoading = true
        val analyzer = InstalledAppAnalyzer(context)
        appList = analyzer.getInstalledApps(includeSystem = false)
        isLoading = false
    }

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        SectionHeader(
            title = "Installed Application Analyzer",
            subtitle = "Audit permissions & target SDK versions (${appList.size} apps)",
            icon = Icons.Default.Apps
        )

        if (isLoading) {
            Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = CyberCyan)
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(appList) { app ->
                    CyberCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.appName, fontWeight = FontWeight.Bold, fontSize = 15.sp, color = TextPrimaryDark)
                                Text(app.packageName, fontSize = 11.sp, color = TextMutedDark, fontFamily = FontFamily.Monospace)
                            }
                            Text(
                                text = "SDK ${app.targetSdkVersion}",
                                fontSize = 12.sp,
                                color = if (app.targetSdkVersion < 31) SeverityHigh else CyberCyan,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("Permissions: ${app.requestedPermissionsCount}", fontSize = 12.sp, color = TextSecondaryDark)
                            Text(
                                text = "Dangerous: ${app.dangerousPermissionsCount}",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (app.dangerousPermissionsCount > 0) CyberAmber else CyberGreen
                            )
                        }
                    }
                }
            }
        }
    }
}
