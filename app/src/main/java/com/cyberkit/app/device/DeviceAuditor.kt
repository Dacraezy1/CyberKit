package com.cyberkit.app.device

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class DeviceSecurityPosture(
    val androidVersion: String,
    val sdkInt: Int,
    val securityPatchDate: String,
    val patchAgeMonths: Long,
    val isDeviceSecure: Boolean, // Screen lock / PIN / Biometrics
    val isStorageEncrypted: Boolean,
    val isDeveloperOptionsEnabled: Boolean,
    val isAdbEnabled: Boolean,
    val isVpnActive: Boolean,
    val isProxyConfigured: Boolean,
    val isInstallNonMarketAllowed: Boolean
)

class DeviceAuditor(private val context: Context) {

    fun auditDevice(): DeviceSecurityPosture {
        val cr = context.contentResolver
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

        val patch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Build.VERSION.SECURITY_PATCH
        } else "Unavailable on this Android version"

        var patchMonths = 0L
        if (patch.length >= 7) {
            try {
                val format = SimpleDateFormat("yyyy-MM", Locale.US)
                val patchTime = format.parse(patch.take(7))?.time ?: 0L
                patchMonths = (System.currentTimeMillis() - patchTime) / (1000L * 60 * 60 * 24 * 30)
            } catch (_: Exception) {}
        }

        val isSecure = km?.isDeviceSecure ?: false
        val encStatus = dpm?.storageEncryptionStatus ?: DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED
        val isEncrypted = encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
                encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER

        val devOptions = try {
            Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (_: Exception) { false }

        val adb = try {
            Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) { false }

        val activeNet = cm?.activeNetwork
        val caps = cm?.getNetworkCapabilities(activeNet)
        val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

        val proxyHost = System.getProperty("http.proxyHost")
        val isProxy = !proxyHost.isNullOrBlank()

        val nonMarket = try {
            @Suppress("DEPRECATION")
            Settings.Secure.getInt(cr, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
        } catch (_: Exception) { false }

        return DeviceSecurityPosture(
            androidVersion = Build.VERSION.RELEASE,
            sdkInt = Build.VERSION.SDK_INT,
            securityPatchDate = patch,
            patchAgeMonths = patchMonths,
            isDeviceSecure = isSecure,
            isStorageEncrypted = isEncrypted || Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
            isDeveloperOptionsEnabled = devOptions,
            isAdbEnabled = adb,
            isVpnActive = isVpn,
            isProxyConfigured = isProxy,
            isInstallNonMarketAllowed = nonMarket
        )
    }

    fun generateAssessmentSummary(posture: DeviceSecurityPosture): AssessmentSummary {
        val findings = mutableListOf<Finding>()

        // 1. Screen Lock
        if (!posture.isDeviceSecure) {
            findings.add(
                Finding(
                    severity = FindingSeverity.CRITICAL,
                    title = "Device Lock Screen Not Configured",
                    description = "No PIN, password, pattern, or biometric screen lock is active. Physical access allows complete unhindered access to device data and credentials.",
                    evidence = "isDeviceSecure = false",
                    target = "Local Device",
                    module = "Device Audit",
                    remediation = "Set up a strong PIN or biometric lock in Device Settings > Security.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 2. Security Patch Age
        if (posture.patchAgeMonths > 6) {
            findings.add(
                Finding(
                    severity = FindingSeverity.HIGH,
                    title = "Security Patch Severely Outdated (${posture.securityPatchDate})",
                    description = "Device security patch is over ${posture.patchAgeMonths} months old, leaving the OS vulnerable to known Android kernel and framework CVEs.",
                    evidence = "Security Patch: ${posture.securityPatchDate}",
                    target = "Android OS",
                    module = "Device Audit",
                    remediation = "Check for system updates in Settings > System > System update.",
                    confidence = FindingConfidence.HIGH
                )
            )
        } else if (posture.patchAgeMonths > 2) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "Security Patch Update Recommended (${posture.securityPatchDate})",
                    description = "Security patch is ${posture.patchAgeMonths} months old.",
                    evidence = "Patch: ${posture.securityPatchDate}",
                    target = "Android OS",
                    module = "Device Audit",
                    remediation = "Apply the latest available monthly security bulletin update.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 3. ADB Debugging
        if (posture.isAdbEnabled) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "USB Debugging (ADB) is Active",
                    description = "ADB enables shell access, application backup extraction, and package installation over USB connections.",
                    evidence = "ADB_ENABLED = 1",
                    target = "Local Device",
                    module = "Device Audit",
                    remediation = "Disable USB debugging when not actively developing applications.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 4. Developer Options
        if (posture.isDeveloperOptionsEnabled) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Developer Options Enabled",
                    description = "Developer settings are unlocked on this device.",
                    evidence = "DEVELOPMENT_SETTINGS_ENABLED = 1",
                    target = "Local Device",
                    module = "Device Audit",
                    remediation = "Disable Developer Options when not required for software engineering.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 5. Proxy configuration
        if (posture.isProxyConfigured) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "HTTP Proxy Active on Device",
                    description = "Network requests may be routed through an external proxy server.",
                    evidence = "Proxy host configured",
                    target = "Network Stack",
                    module = "Device Audit",
                    remediation = "Ensure any configured proxy server is intentional and authorized.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 6. VPN
        if (posture.isVpnActive) {
            findings.add(
                Finding(
                    severity = FindingSeverity.INFO,
                    title = "VPN Tunnel Active",
                    description = "A Virtual Private Network is currently routing device network traffic.",
                    evidence = "NetworkCapabilities.TRANSPORT_VPN = true",
                    target = "Network Stack",
                    module = "Device Audit",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "Device Security Posture",
            target = "${Build.MANUFACTURER} ${Build.MODEL}",
            module = "Device Audit",
            score = score,
            findings = findings,
            metadata = mapOf(
                "Model" to "${Build.MANUFACTURER} ${Build.MODEL}",
                "OS Version" to "Android ${posture.androidVersion} (API ${posture.sdkInt})",
                "Patch Date" to posture.securityPatchDate,
                "Lock Screen" to if (posture.isDeviceSecure) "Protected" else "Unsecured",
                "Storage Encryption" to if (posture.isStorageEncrypted) "Active" else "Inactive",
                "ADB Debugging" to if (posture.isAdbEnabled) "Enabled" else "Disabled"
            )
        )
    }
}
