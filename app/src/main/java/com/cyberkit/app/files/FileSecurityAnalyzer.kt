package com.cyberkit.app.files

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

data class FileAssessmentResult(
    val fileName: String,
    val fileSize: Long,
    val mimeType: String,
    val entropy: Double,
    val md5: String,
    val sha256: String,
    val riskCategory: String, // "Clean-looking", "Potentially suspicious", "High-risk indicators detected", "Unable to determine"
    val archiveInspection: ArchiveInspectionResult?,
    val secretsFound: List<SecretMatch>,
    val findings: List<Finding>
)

class FileSecurityAnalyzer {

    suspend fun analyzeFile(file: File): FileAssessmentResult = withContext(Dispatchers.IO) {
        val size = file.length()
        val entropy = EntropyCalculator.calculateFileEntropy(file)
        val hashes = calculateHashes(file)
        val mime = detectMimeType(file)

        val findings = mutableListOf<Finding>()

        // 1. Check file extension anomalies & magic bytes
        val magicIndicator = detectExecutableMagicBytes(file)
        if (magicIndicator != null) {
            findings.add(
                Finding(
                    severity = FindingSeverity.HIGH,
                    title = "Executable Binary Magic Bytes Detected ($magicIndicator)",
                    description = "File contains header markers for binary executable code ($magicIndicator). Heuristic evaluation only; does not confirm malicious intent.",
                    evidence = "Format marker: $magicIndicator in ${file.name}",
                    target = file.name,
                    module = "File Security",
                    remediation = "Verify binary provenance and compile origin before execution.",
                    confidence = FindingConfidence.MEDIUM
                )
            )
        }

        // 2. Entropy analysis
        if (entropy > 7.4) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "High Shannon Entropy (${String.format("%.2f", entropy)} / 8.0)",
                    description = "High entropy indicates content is compressed, packed, or encrypted. Packers are frequently used by modern software to compress assets or obfuscate code.",
                    evidence = "Entropy: ${String.format("%.2f", entropy)}",
                    target = file.name,
                    module = "File Security",
                    remediation = "Inspect uncompressed contents to evaluate components.",
                    confidence = FindingConfidence.LOW
                )
            )
        }

        // 3. Archive inspection if ZIP/JAR/APK
        var archiveResult: ArchiveInspectionResult? = null
        val lowerName = file.name.lowercase()
        if (lowerName.endsWith(".zip") || lowerName.endsWith(".jar") || lowerName.endsWith(".apk")) {
            val insp = ArchiveInspector.inspectZipFile(file)
            archiveResult = insp
            if (insp.hasZipSlipPathTraversal) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.CRITICAL,
                        title = "Zip Slip (Path Traversal) Detected in Archive",
                        description = "Archive contains filenames with '../' designed to escape the target extraction directory and overwrite arbitrary local files.",
                        evidence = "Suspicious entries: ${insp.suspiciousEntries.map { it.name }.take(3).joinToString()}",
                        target = file.name,
                        module = "File Security",
                        remediation = "Do not extract this archive using unvalidated extraction utilities.",
                        confidence = FindingConfidence.HIGH
                    )
                )
            }
            if (insp.suspiciousEntries.isNotEmpty() && !lowerName.endsWith(".apk")) {
                findings.add(
                    Finding(
                        severity = FindingSeverity.MEDIUM,
                        title = "${insp.suspiciousEntries.size} Suspicious Executable/Script Entry Found",
                        description = "Found nested executables or scripts inside the archive (${insp.suspiciousEntries.take(3).map { it.name }.joinToString()}).",
                        evidence = "Nested files detected",
                        target = file.name,
                        module = "File Security",
                        confidence = FindingConfidence.MEDIUM
                    )
                )
            }
        }

        // 4. Secret scan for readable text/config files
        val secrets = if (isTextFile(file)) {
            val sc = SecretScanner.scanTextFile(file)
            findings.addAll(SecretScanner.toFindings(sc, file.name))
            sc
        } else emptyList()

        val riskCategory = when {
            findings.any { it.severity == FindingSeverity.CRITICAL } -> "High-risk indicators detected"
            findings.any { it.severity == FindingSeverity.HIGH || it.severity == FindingSeverity.MEDIUM } -> "Potentially suspicious"
            findings.isNotEmpty() -> "Clean-looking (Minor notes)"
            else -> "Clean-looking"
        }

        FileAssessmentResult(
            fileName = file.name,
            fileSize = size,
            mimeType = mime,
            entropy = entropy,
            md5 = hashes.first,
            sha256 = hashes.second,
            riskCategory = riskCategory,
            archiveInspection = archiveResult,
            secretsFound = secrets,
            findings = findings
        )
    }

    private fun detectExecutableMagicBytes(file: File): String? {
        if (!file.exists() || file.length() < 4) return null
        val header = ByteArray(4)
        file.inputStream().use { it.read(header) }

        return when {
            header[0] == 0x7F.toByte() && header[1] == 'E'.code.toByte() && header[2] == 'L'.code.toByte() && header[3] == 'F'.code.toByte() -> "Linux ELF Binary"
            header[0] == 'M'.code.toByte() && header[1] == 'Z'.code.toByte() -> "Windows PE / MZ Executable"
            header[0] == 'd'.code.toByte() && header[1] == 'e'.code.toByte() && header[2] == 'x'.code.toByte() && header[3] == '\n'.code.toByte() -> "Android Dalvik Executable (DEX)"
            header[0] == '#'.code.toByte() && header[1] == '!'.code.toByte() -> "Shell Script Shebang"
            header[0] == 0xCA.toByte() && header[1] == 0xFE.toByte() && header[2] == 0xBA.toByte() && header[3] == 0xBE.toByte() -> "Java Class / Mach-O Fat Binary"
            else -> null
        }
    }

    private fun detectMimeType(file: File): String {
        val ext = file.extension.lowercase()
        return when (ext) {
            "apk" -> "application/vnd.android.package-archive"
            "zip" -> "application/zip"
            "jar" -> "application/java-archive"
            "json" -> "application/json"
            "xml" -> "application/xml"
            "txt", "md", "log" -> "text/plain"
            "sh", "bash" -> "application/x-sh"
            "py" -> "text/x-python"
            else -> "application/octet-stream"
        }
    }

    private fun isTextFile(file: File): Boolean {
        val ext = file.extension.lowercase()
        return ext in listOf("txt", "json", "xml", "yaml", "yml", "properties", "conf", "ini", "log", "sh", "py", "java", "kt", "js", "html")
    }

    private fun calculateHashes(file: File): Pair<String, String> {
        val md5 = MessageDigest.getInstance("MD5")
        val sha256 = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val buf = ByteArray(8192)
            var read: Int
            while (stream.read(buf).also { read = it } != -1) {
                md5.update(buf, 0, read)
                sha256.update(buf, 0, read)
            }
        }
        return Pair(
            md5.digest().joinToString("") { String.format("%02x", it) },
            sha256.digest().joinToString("") { String.format("%02x", it) }
        )
    }

    fun generateAssessmentSummary(result: FileAssessmentResult): AssessmentSummary {
        val score = AssessmentSummary.calculateScore(result.findings)
        return AssessmentSummary(
            title = "File Audit: ${result.fileName}",
            target = result.fileName,
            module = "File Security",
            score = score,
            findings = result.findings,
            metadata = mapOf(
                "Risk Category" to result.riskCategory,
                "Size" to "${result.fileSize / 1024} KB",
                "Entropy" to "${String.format("%.2f", result.entropy)} / 8.0",
                "SHA-256" to result.sha256,
                "Notice" to "Heuristic static analysis does not replace full endpoint antivirus protection."
            )
        )
    }
}
