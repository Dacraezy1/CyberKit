package com.cyberkit.app.files

import java.io.File
import java.util.zip.ZipFile

data class ArchiveEntryDetail(
    val name: String,
    val size: Long,
    val compressedSize: Long,
    val isDirectory: Boolean,
    val isSuspicious: Boolean,
    val suspiciousReason: String? = null
)

data class ArchiveInspectionResult(
    val totalEntries: Int,
    val totalUncompressedBytes: Long,
    val hasZipSlipPathTraversal: Boolean,
    val suspiciousEntries: List<ArchiveEntryDetail>,
    val entries: List<ArchiveEntryDetail>
)

object ArchiveInspector {

    private val SUSPICIOUS_EXTENSIONS = setOf(
        ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".bash", ".elf", ".so", ".dll", ".dex", ".apk", ".scr"
    )

    fun inspectZipFile(file: File, maxEntries: Int = 500): ArchiveInspectionResult {
        var totalEntries = 0
        var totalUncompressed = 0L
        var hasZipSlip = false
        val suspicious = mutableListOf<ArchiveEntryDetail>()
        val allEntries = mutableListOf<ArchiveEntryDetail>()

        try {
            ZipFile(file).use { zip ->
                val enumEntries = zip.entries()
                while (enumEntries.hasMoreElements()) {
                    val entry = enumEntries.nextElement()
                    totalEntries++
                    totalUncompressed += entry.size

                    val name = entry.name
                    var isSusp = false
                    var reason: String? = null

                    // 1. Path traversal check (Zip Slip vulnerability)
                    if (name.contains("../") || name.contains("..\\") || name.startsWith("/")) {
                        hasZipSlip = true
                        isSusp = true
                        reason = "Path Traversal (Zip Slip) attempt detected: $name"
                    }

                    // 2. Suspicious file extensions in unexpected archives
                    val lower = name.lowercase()
                    val ext = SUSPICIOUS_EXTENSIONS.firstOrNull { lower.endsWith(it) }
                    if (ext != null && !file.name.endsWith(".apk", ignoreCase = true)) {
                        isSusp = true
                        reason = (reason?.plus("; ") ?: "") + "Embedded executable/script ($ext)"
                    }

                    val detail = ArchiveEntryDetail(
                        name = name,
                        size = entry.size,
                        compressedSize = entry.compressedSize,
                        isDirectory = entry.isDirectory,
                        isSuspicious = isSusp,
                        suspiciousReason = reason
                    )

                    if (isSusp) {
                        suspicious.add(detail)
                    }
                    if (allEntries.size < maxEntries) {
                        allEntries.add(detail)
                    }
                }
            }
        } catch (_: Exception) {}

        return ArchiveInspectionResult(
            totalEntries = totalEntries,
            totalUncompressedBytes = totalUncompressed,
            hasZipSlipPathTraversal = hasZipSlip,
            suspiciousEntries = suspicious,
            entries = allEntries
        )
    }
}
