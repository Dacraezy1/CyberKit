package com.cyberkit.app.ui.screens.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberkit.app.core.database.CyberKitDatabase
import com.cyberkit.app.core.theme.*
import com.cyberkit.app.device.DeviceAuditor
import com.cyberkit.app.network.WifiAnalyzer
import com.cyberkit.app.ui.components.CyberCard
import com.cyberkit.app.ui.components.ScoreBadge
import com.cyberkit.app.ui.components.SectionHeader
import com.cyberkit.app.ui.navigation.Screen

@Composable
fun DashboardScreen(
    onNavigate: (Screen) -> Unit
) {
    val context = LocalContext.current
    val db = remember { CyberKitDatabase.getDatabase(context) }
    val scanCount by db.scanDao().getScanCount().collectAsState(initial = 0)

    val wifiDetails = remember { WifiAnalyzer(context).getWifiDetails() }
    val devicePosture = remember { DeviceAuditor(context).auditDevice() }

    val securityScore = remember(devicePosture, wifiDetails) {
        var score = 100
        if (!devicePosture.isDeviceSecure) score -= 30
        if (devicePosture.patchAgeMonths > 6) score -= 20
        if (devicePosture.isAdbEnabled) score -= 10
        if (wifiDetails.isConnected && wifiDetails.securityType.contains("Open")) score -= 25
        score.coerceIn(20, 100)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberBgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Top Brand Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "CYBERKIT",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Black,
                    fontFamily = FontFamily.Monospace,
                    color = CyberCyan,
                    letterSpacing = 1.5.sp
                )
                Text(
                    text = "Mobile Cybersecurity Workstation",
                    fontSize = 12.sp,
                    color = TextSecondaryDark
                )
            }

            Box(
                modifier = Modifier
                    .clip(CircleShape)
                    .background(if (devicePosture.isDeviceSecure) CyberGreen.copy(alpha = 0.2f) else SeverityCritical.copy(alpha = 0.2f))
                    .padding(horizontal = 10.dp, vertical = 4.dp)
            ) {
                Text(
                    text = if (devicePosture.isDeviceSecure) "PROTECTED" else "ATTENTION",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (devicePosture.isDeviceSecure) CyberGreen else SeverityCritical,
                    fontFamily = FontFamily.Monospace
                )
            }
        }

        // Security Score Banner
        CyberCard(
            modifier = Modifier.fillMaxWidth(),
            borderColor = CyberCyan.copy(alpha = 0.4f)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "SECURITY POSTURE SCORE",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = CyberCyan,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Composite Device & Local Network Evaluation",
                        fontSize = 13.sp,
                        color = TextSecondaryDark
                    )
                }
                ScoreBadge(score = securityScore)
            }

            Spacer(modifier = Modifier.height(12.dp))
            LinearProgressIndicator(
                progress = { securityScore / 100f },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp)),
                color = if (securityScore >= 80) CyberGreen else CyberAmber,
                trackColor = CyberBgDark,
            )
        }

        // Live Telemetry Grid
        Text(
            text = "LIVE TELEMETRY",
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = TextMutedDark,
            fontFamily = FontFamily.Monospace
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Wi-Fi Status
            CyberCard(
                modifier = Modifier.weight(1f)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (wifiDetails.isConnected) Icons.Default.Wifi else Icons.Default.WifiOff,
                        contentDescription = null,
                        tint = if (wifiDetails.isConnected) CyberCyan else TextMutedDark,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Wi-Fi Network",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextSecondaryDark
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = wifiDetails.ssid,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimaryDark,
                    maxLines = 1
                )
                Text(
                    text = if (wifiDetails.isConnected) "${wifiDetails.signalPercent}% (${wifiDetails.rssi} dBm)" else "Offline",
                    fontSize = 11.sp,
                    color = TextMutedDark
                )
            }

            // Device Posture
            CyberCard(
                modifier = Modifier.weight(1f)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = if (devicePosture.isDeviceSecure) CyberGreen else CyberAmber,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Lock Screen",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextSecondaryDark
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = if (devicePosture.isDeviceSecure) "Configured (Secure)" else "None (Vulnerable)",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = if (devicePosture.isDeviceSecure) CyberGreen else SeverityCritical
                )
                Text(
                    text = "Patch: ${devicePosture.securityPatchDate}",
                    fontSize = 11.sp,
                    color = TextMutedDark
                )
            }
        }

        // Quick Smart Audit Banner
        CyberCard(
            modifier = Modifier.fillMaxWidth(),
            onClick = { onNavigate(Screen.SmartAudit) },
            backgroundColor = Color(0xFF0D2538),
            borderColor = CyberCyan
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.SecurityUpdateGood,
                        contentDescription = null,
                        tint = CyberCyan,
                        modifier = Modifier.size(32.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "SMART AUDIT",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            color = CyberCyan,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = "Automated multi-tool assessment for your device, network, or apps",
                            fontSize = 12.sp,
                            color = TextSecondaryDark
                        )
                    }
                }
                Icon(
                    imageVector = Icons.Default.ArrowForwardIos,
                    contentDescription = null,
                    tint = CyberCyan,
                    modifier = Modifier.size(16.dp)
                )
            }
        }

        // Assessment Workstation Modules
        SectionHeader(
            title = "Security Assessment Tools",
            subtitle = "Authorized diagnostics & cybersecurity utilities",
            icon = Icons.Default.Apps
        )

        val toolCards = listOf(
            ToolItem("Network Recon & Port Scanner", "TCP scanning, host discovery, subnetting & Wi-Fi", Icons.Default.Router, Screen.Network),
            ToolItem("Web & TLS Analyzer", "URL syntax, security headers, cert chain audit", Icons.Default.Public, Screen.Web),
            ToolItem("APK & File Security", "Manifest parsing, secrets, entropy & signatures", Icons.Default.FolderZip, Screen.Apk),
            ToolItem("Device Security Audit", "OS posture, encryption & permission analysis", Icons.Default.PermDeviceInformation, Screen.Device),
            ToolItem("Crypto Toolkit & CVSS", "Hashes, HMAC, encoders, password & CVSS v3.1", Icons.Default.Lock, Screen.Crypto),
            ToolItem("Security Reports & History", "Recorded assessments ($scanCount) & export tools", Icons.Default.Assessment, Screen.Reports),
            ToolItem("Cybersecurity Labs", "Offline simulated training & conceptual labs", Icons.Default.MenuBook, Screen.Labs),
            ToolItem("CyberKit Console", "Interactive workstation CLI interface", Icons.Default.Terminal, Screen.Terminal)
        )

        for (item in toolCards) {
            CyberCard(
                modifier = Modifier.fillMaxWidth(),
                onClick = { onNavigate(item.screen) }
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(CyberBgDark)
                                .border(1.dp, CyberCardBorder, RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = item.icon,
                                contentDescription = null,
                                tint = CyberCyan,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = item.title,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimaryDark
                            )
                            Text(
                                text = item.subtitle,
                                fontSize = 12.sp,
                                color = TextSecondaryDark
                            )
                        }
                    }
                    Icon(
                        imageVector = Icons.Default.ChevronRight,
                        contentDescription = null,
                        tint = TextMutedDark,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }
}

private data class ToolItem(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val screen: Screen
)
