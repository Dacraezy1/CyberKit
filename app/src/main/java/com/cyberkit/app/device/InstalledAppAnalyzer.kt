package com.cyberkit.app.device

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledAppInfo(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val targetSdkVersion: Int,
    val isSystemApp: Boolean,
    val requestedPermissionsCount: Int,
    val dangerousPermissionsCount: Int,
    val dangerousPermissionsList: List<String>,
    val riskScore: Int // 0 - 100
)

class InstalledAppAnalyzer(private val context: Context) {

    private val DANGEROUS_PERMISSIONS = setOf(
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW"
    )

    suspend fun getInstalledApps(includeSystem: Boolean = false): List<InstalledAppInfo> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val list = mutableListOf<InstalledAppInfo>()

        try {
            val flags = PackageManager.GET_PERMISSIONS
            val packages = pm.getInstalledPackages(flags)

            for (pkg in packages) {
                val isSys = (pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                if (!includeSystem && isSys) continue

                val appName = try {
                    pkg.applicationInfo.loadLabel(pm).toString()
                } catch (_: Exception) {
                    pkg.packageName
                }

                val requestedPerms = pkg.requestedPermissions ?: emptyArray()
                val dangerousPerms = requestedPerms.filter { it in DANGEROUS_PERMISSIONS }

                var penalty = 0
                if (pkg.applicationInfo.targetSdkVersion < 31) penalty += 15
                penalty += (dangerousPerms.size * 5)
                val riskScore = (100 - penalty).coerceIn(10, 100)

                list.add(
                    InstalledAppInfo(
                        packageName = pkg.packageName,
                        appName = appName,
                        versionName = pkg.versionName ?: "1.0",
                        targetSdkVersion = pkg.applicationInfo.targetSdkVersion,
                        isSystemApp = isSys,
                        requestedPermissionsCount = requestedPerms.size,
                        dangerousPermissionsCount = dangerousPerms.size,
                        dangerousPermissionsList = dangerousPerms,
                        riskScore = riskScore
                    )
                )
            }
        } catch (_: Exception) {}

        list.sortedBy { it.riskScore }
    }

    fun generateAssessmentSummary(apps: List<InstalledAppInfo>): AssessmentSummary {
        val findings = mutableListOf<Finding>()

        val highRiskApps = apps.filter { it.dangerousPermissionsCount >= 4 }
        if (highRiskApps.isNotEmpty()) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "${highRiskApps.size} Installed App(s) With Multiple Dangerous Permissions",
                    description = "Apps requesting 4 or more sensitive permissions (e.g. camera, audio, fine location, contacts).",
                    evidence = "Apps: ${highRiskApps.take(5).joinToString { "${it.appName} (${it.dangerousPermissionsCount} perms)" }}",
                    target = "Installed Applications",
                    module = "App Analyzer",
                    remediation = "Audit application permissions in Android Settings > Privacy > Permission manager.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        val outdatedApps = apps.filter { it.targetSdkVersion < 29 }
        if (outdatedApps.isNotEmpty()) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "${outdatedApps.size} Outdated Application(s) (Target SDK < 29)",
                    description = "Applications built against legacy Android APIs bypass scoped storage and background permission restrictions.",
                    evidence = "Apps: ${outdatedApps.take(4).joinToString { it.appName }}",
                    target = "Installed Applications",
                    module = "App Analyzer",
                    remediation = "Update or uninstall unmaintained legacy applications.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "Installed Applications Audit",
            target = "User Applications (${apps.size})",
            module = "App Analyzer",
            score = score,
            findings = findings,
            metadata = mapOf(
                "Total Scanned" to apps.size.toString(),
                "High Risk App Count" to highRiskApps.size.toString(),
                "Legacy SDK Apps" to outdatedApps.size.toString()
            )
        )
    }
}
