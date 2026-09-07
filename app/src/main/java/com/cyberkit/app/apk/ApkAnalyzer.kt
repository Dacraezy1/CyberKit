package com.cyberkit.app.apk

import android.content.Context
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipFile

data class ManifestComponent(
    val type: String, // activity, service, receiver, provider
    val name: String,
    val isExported: Boolean,
    val permission: String? = null
)

data class ApkAnalysisResult(
    val fileName: String,
    val fileSize: Long,
    val packageName: String,
    val versionName: String,
    val versionCode: Int,
    val minSdkVersion: Int,
    val targetSdkVersion: Int,
    val isDebuggable: Boolean,
    val allowBackup: Boolean,
    val usesCleartextTraffic: Boolean,
    val hasNetworkSecurityConfig: Boolean,
    val permissions: List<String>,
    val dangerousPermissions: List<String>,
    val components: List<ManifestComponent>,
    val nativeLibraries: List<String>,
    val hardcodedUrls: List<String>,
    val hashes: ApkHashes,
    val certificates: List<ApkCertificateInfo>,
    val decodedManifestXml: String
)

class ApkAnalyzer(private val context: Context) {

    private val DANGEROUS_PERMISSIONS = setOf(
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.BODY_SENSORS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES"
    )

    suspend fun analyzeApkFile(apkFile: File): ApkAnalysisResult = withContext(Dispatchers.IO) {
        val hashes = SignatureVerifier.calculateHashes(apkFile)
        val certs = SignatureVerifier.extractCertificates(apkFile)

        var manifestXml = ""
        val nativeLibs = mutableListOf<String>()
        val hardcodedUrls = mutableListOf<String>()

        ZipFile(apkFile).use { zip ->
            val manifestEntry = zip.getEntry("AndroidManifest.xml")
            if (manifestEntry != null) {
                zip.getInputStream(manifestEntry).use { inStream ->
                    val bytes = inStream.readBytes()
                    manifestXml = AxmlDecoder.decode(bytes)
                }
            }

            // Inspect entries for native libs and DEX strings
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val name = entry.name
                if (name.startsWith("lib/") && name.endsWith(".so")) {
                    nativeLibs.add(name)
                } else if (name.startsWith("classes") && name.endsWith(".dex") && hardcodedUrls.size < 20) {
                    // Extract printable URL strings from DEX header/data
                    try {
                        zip.getInputStream(entry).use { inStream ->
                            val sampleBytes = ByteArray(minOf(entry.size.toInt(), 500_000))
                            inStream.read(sampleBytes)
                            val dexString = String(sampleBytes, Charsets.ISO_8859_1)
                            val urlRegex = Regex("http[s]?://[a-zA-Z0-9.\\-_]+(?:/[a-zA-Z0-9.\\-_~:?#\\[\\]@!$&'()*+,;=]*)?")
                            for (match in urlRegex.findAll(dexString).take(10)) {
                                val u = match.value
                                if (!u.contains("schemas.android.com") && !u.contains("w3.org") && !hardcodedUrls.contains(u)) {
                                    hardcodedUrls.add(u)
                                }
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
        }

        // Parse extracted manifest XML
        val pkg = extractAttribute(manifestXml, "package") ?: "unknown"
        val vCode = extractAttribute(manifestXml, "versionCode")?.toIntOrNull() ?: 1
        val vName = extractAttribute(manifestXml, "versionName") ?: "1.0"
        val minSdk = extractAttribute(manifestXml, "minSdkVersion")?.toIntOrNull() ?: 21
        val targetSdk = extractAttribute(manifestXml, "targetSdkVersion")?.toIntOrNull() ?: 30

        val isDebug = manifestXml.contains("android:debuggable=\"true\"")
        val allowBackup = !manifestXml.contains("android:allowBackup=\"false\"") // Default is true if omitted
        val usesCleartext = manifestXml.contains("android:usesCleartextTraffic=\"true\"")
        val hasNetSec = manifestXml.contains("android:networkSecurityConfig")

        // Parse permissions
        val permissions = mutableListOf<String>()
        val permRegex = Regex("<uses-permission[^>]*android:name=\"([^\"]+)\"")
        permRegex.findAll(manifestXml).forEach { match ->
            permissions.add(match.groupValues[1])
        }

        val dangerous = permissions.filter { it in DANGEROUS_PERMISSIONS }

        // Parse components
        val components = mutableListOf<ManifestComponent>()
        val componentTypes = listOf("activity", "service", "receiver", "provider")
        for (type in componentTypes) {
            val compRegex = Regex("<$type[^>]*android:name=\"([^\"]+)\"[^>]*>", RegexOption.DOT_MATCHES_ALL)
            compRegex.findAll(manifestXml).forEach { match ->
                val block = match.value
                val name = match.groupValues[1]
                val isExp = block.contains("android:exported=\"true\"")
                val perm = extractAttribute(block, "permission")
                components.add(ManifestComponent(type, name, isExp, perm))
            }
        }

        ApkAnalysisResult(
            fileName = apkFile.name,
            fileSize = apkFile.length(),
            packageName = pkg,
            versionName = vName,
            versionCode = vCode,
            minSdkVersion = minSdk,
            targetSdkVersion = targetSdk,
            isDebuggable = isDebug,
            allowBackup = allowBackup,
            usesCleartextTraffic = usesCleartext,
            hasNetworkSecurityConfig = hasNetSec,
            permissions = permissions.distinct(),
            dangerousPermissions = dangerous.distinct(),
            components = components,
            nativeLibraries = nativeLibs,
            hardcodedUrls = hardcodedUrls,
            hashes = hashes,
            certificates = certs,
            decodedManifestXml = manifestXml
        )
    }

    private fun extractAttribute(xml: String, attrName: String): String? {
        val regex = Regex("android:$attrName=\"([^\"]+)\"")
        return regex.find(xml)?.groupValues?.get(1)
    }

    fun generateAssessmentSummary(result: ApkAnalysisResult): AssessmentSummary {
        val findings = mutableListOf<Finding>()

        // 1. Debuggable check
        if (result.isDebuggable) {
            findings.add(
                Finding(
                    severity = FindingSeverity.CRITICAL,
                    title = "Application is Flagged as Debuggable",
                    description = "The APK has android:debuggable='true'. Anyone with adb access can attach a debugger, extract memory, and execute code within the app's UID.",
                    evidence = "android:debuggable=\"true\" in AndroidManifest.xml",
                    target = result.packageName,
                    module = "APK Analyzer",
                    remediation = "Set android:debuggable='false' in release builds.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 2. Cleartext traffic
        if (result.usesCleartextTraffic) {
            findings.add(
                Finding(
                    severity = FindingSeverity.HIGH,
                    title = "Cleartext Network Traffic Explicitly Enabled",
                    description = "The APK explicitly enables unencrypted HTTP network traffic (android:usesCleartextTraffic='true').",
                    evidence = "android:usesCleartextTraffic=\"true\"",
                    target = result.packageName,
                    module = "APK Analyzer",
                    remediation = "Enforce HTTPS traffic and use a Network Security Configuration file.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 3. Backup enabled
        if (result.allowBackup) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "Application Data Backup Enabled (allowBackup=true)",
                    description = "Users or attackers with adb access can dump private application databases and shared preferences via 'adb backup'.",
                    evidence = "android:allowBackup=\"true\"",
                    target = result.packageName,
                    module = "APK Analyzer",
                    remediation = "Set android:allowBackup='false' if the app manages sensitive credentials or tokens.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 4. Target SDK check
        if (result.targetSdkVersion < 31) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "Outdated Target SDK Version (${result.targetSdkVersion})",
                    description = "Targeting Android versions below API 31 misses modern security sandboxing, scoped storage, and exported component enforcement.",
                    evidence = "targetSdkVersion=${result.targetSdkVersion}",
                    target = result.packageName,
                    module = "APK Analyzer",
                    remediation = "Update targetSdkVersion to API 34.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 5. Exported components without permissions
        val exportedWithoutPerm = result.components.filter { it.isExported && it.permission.isNullOrBlank() }
        if (exportedWithoutPerm.isNotEmpty()) {
            findings.add(
                Finding(
                    severity = FindingSeverity.HIGH,
                    title = "${exportedWithoutPerm.size} Exported Component(s) Without Permissions",
                    description = "Activities, Services, or Receivers are exported and unprotected, allowing any third-party app on the device to invoke them directly.",
                    evidence = "Exported: ${exportedWithoutPerm.take(5).joinToString { "${it.type}:${it.name}" }}",
                    target = result.packageName,
                    module = "APK Analyzer",
                    remediation = "Set android:exported='false' on internal components or enforce custom android:permission checks.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 6. Dangerous permissions
        if (result.dangerousPermissions.isNotEmpty()) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "${result.dangerousPermissions.size} Dangerous Permission(s) Requested",
                    description = "The app requests sensitive capabilities (e.g. location, camera, storage, microphone).",
                    evidence = "Permissions: ${result.dangerousPermissions.take(6).joinToString()}",
                    target = result.packageName,
                    module = "APK Analyzer",
                    remediation = "Apply the Principle of Least Privilege and request only permissions strictly required.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        // 7. Hardcoded plain HTTP URLs in DEX
        val plainHttpUrls = result.hardcodedUrls.filter { it.startsWith("http://") }
        if (plainHttpUrls.isNotEmpty()) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Cleartext HTTP URL Strings Embedded in Code",
                    description = "Found unencrypted HTTP endpoint references in application bytecode.",
                    evidence = "URLs: ${plainHttpUrls.take(3).joinToString()}",
                    target = result.packageName,
                    module = "APK Analyzer",
                    remediation = "Migrate all hardcoded API endpoints to https://.",
                    confidence = FindingConfidence.MEDIUM
                )
            )
        }

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "APK Audit: ${result.packageName}",
            target = result.packageName,
            module = "APK Analyzer",
            score = score,
            findings = findings,
            metadata = mapOf(
                "Version" to "${result.versionName} (${result.versionCode})",
                "SDK Targets" to "min=${result.minSdkVersion}, target=${result.targetSdkVersion}",
                "Size" to "${result.fileSize / 1024} KB",
                "SHA-256" to result.hashes.sha256,
                "Exported Components" to exportedWithoutPerm.size.toString(),
                "Native Libraries" to result.nativeLibraries.size.toString()
            )
        )
    }
}
