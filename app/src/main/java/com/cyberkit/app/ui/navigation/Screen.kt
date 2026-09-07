package com.cyberkit.app.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MenuBook
import androidx.compose.material.icons.filled.PermDeviceInformation
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.ui.graphics.vector.ImageVector

sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object Dashboard : Screen("dashboard", "Dashboard", Icons.Default.Dashboard)
    object Network : Screen("network", "Network", Icons.Default.Router)
    object Web : Screen("web", "Web & TLS", Icons.Default.Public)
    object Apk : Screen("apk", "APK & Files", Icons.Default.FolderZip)
    object Device : Screen("device", "Device", Icons.Default.PermDeviceInformation)
    object Crypto : Screen("crypto", "Crypto & CVSS", Icons.Default.Lock)
    object SmartAudit : Screen("smart_audit", "Smart Audit", Icons.Default.Security)
    object Reports : Screen("reports", "Reports", Icons.Default.Assessment)
    object Labs : Screen("labs", "Labs", Icons.Default.MenuBook)
    object Terminal : Screen("terminal", "Console", Icons.Default.Terminal)

    companion object {
        val bottomNavItems = listOf(
            Dashboard,
            Network,
            Web,
            Apk,
            SmartAudit,
            Reports,
            Terminal
        )
    }
}
