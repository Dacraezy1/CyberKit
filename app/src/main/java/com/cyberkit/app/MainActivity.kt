package com.cyberkit.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.cyberkit.app.core.theme.CyberBgDark
import com.cyberkit.app.core.theme.CyberCyan
import com.cyberkit.app.core.theme.CyberKitTheme
import com.cyberkit.app.core.theme.CyberSurfaceDark
import com.cyberkit.app.core.theme.TextMutedDark
import com.cyberkit.app.ui.navigation.Screen
import com.cyberkit.app.ui.screens.apk.ApkScreen
import com.cyberkit.app.ui.screens.crypto.CryptoScreen
import com.cyberkit.app.ui.screens.dashboard.DashboardScreen
import com.cyberkit.app.ui.screens.device.DeviceScreen
import com.cyberkit.app.ui.screens.labs.LabsScreen
import com.cyberkit.app.ui.screens.network.NetworkScreen
import com.cyberkit.app.ui.screens.reports.ReportsScreen
import com.cyberkit.app.ui.screens.smartaudit.SmartAuditScreen
import com.cyberkit.app.ui.screens.terminal.TerminalScreen
import com.cyberkit.app.ui.screens.web.WebScreen

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CyberKitTheme(darkTheme = true) {
                MainAppScaffold()
            }
        }
    }
}

@Composable
fun MainAppScaffold() {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = CyberSurfaceDark,
                contentColor = CyberCyan,
                tonalElevation = 8.dp
            ) {
                Screen.bottomNavItems.forEach { screen ->
                    val selected = currentRoute == screen.route
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            if (currentRoute != screen.route) {
                                navController.navigate(screen.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        },
                        icon = {
                            Icon(
                                imageVector = screen.icon,
                                contentDescription = screen.title,
                                tint = if (selected) CyberCyan else TextMutedDark
                            )
                        },
                        label = {
                            Text(
                                text = screen.title,
                                fontSize = 10.sp,
                                color = if (selected) CyberCyan else TextMutedDark
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = Color(0xFF0C2436)
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(CyberBgDark)
                .padding(innerPadding)
        ) {
            NavHost(
                navController = navController,
                startDestination = Screen.Dashboard.route
            ) {
                composable(Screen.Dashboard.route) {
                    DashboardScreen(onNavigate = { targetScreen ->
                        navController.navigate(targetScreen.route)
                    })
                }
                composable(Screen.Network.route) { NetworkScreen() }
                composable(Screen.Web.route) { WebScreen() }
                composable(Screen.Apk.route) { ApkScreen() }
                composable(Screen.Device.route) { DeviceScreen() }
                composable(Screen.Crypto.route) { CryptoScreen() }
                composable(Screen.SmartAudit.route) { SmartAuditScreen() }
                composable(Screen.Reports.route) { ReportsScreen() }
                composable(Screen.Labs.route) { LabsScreen() }
                composable(Screen.Terminal.route) { TerminalScreen() }
            }
        }
    }
}
