package com.cyberkit.app.apk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.jar.JarFile

data class ApkHashes(
    val md5: String,
    val sha1: String,
    val sha256: String,
    val sha512: String
)

data class ApkCertificateInfo(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val sigAlgName: String,
    val sha1Fingerprint: String,
    val sha256Fingerprint: String
)

object SignatureVerifier {

    suspend fun calculateHashes(file: File): ApkHashes = withContext(Dispatchers.IO) {
        val md5 = MessageDigest.getInstance("MD5")
        val sha1 = MessageDigest.getInstance("SHA-1")
        val sha256 = MessageDigest.getInstance("SHA-256")
        val sha512 = MessageDigest.getInstance("SHA-512")

        file.inputStream().use { stream ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (stream.read(buffer).also { bytesRead = it } != -1) {
                md5.update(buffer, 0, bytesRead)
                sha1.update(buffer, 0, bytesRead)
                sha256.update(buffer, 0, bytesRead)
                sha512.update(buffer, 0, bytesRead)
            }
        }

        ApkHashes(
            md5 = bytesToHex(md5.digest()),
            sha1 = bytesToHex(sha1.digest()),
            sha256 = bytesToHex(sha256.digest()),
            sha512 = bytesToHex(sha512.digest())
        )
    }

    suspend fun extractCertificates(apkFile: File): List<ApkCertificateInfo> = withContext(Dispatchers.IO) {
        val certs = mutableListOf<ApkCertificateInfo>()
        try {
            JarFile(apkFile).use { jar ->
                val entries = jar.entries()
                val certFactory = CertificateFactory.getInstance("X.509")

                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name.uppercase()
                    if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                        jar.getInputStream(entry).use { inStream ->
                            try {
                                val certCollection = certFactory.generateCertificates(inStream)
                                for (c in certCollection) {
                                    if (c is X509Certificate) {
                                        certs.add(
                                            ApkCertificateInfo(
                                                subject = c.subjectX500Principal.name,
                                                issuer = c.issuerX500Principal.name,
                                                serialNumber = c.serialNumber.toString(16),
                                                sigAlgName = c.sigAlgName,
                                                sha1Fingerprint = getCertFingerprint(c, "SHA-1"),
                                                sha256Fingerprint = getCertFingerprint(c, "SHA-256")
                                            )
                                        )
                                    }
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }
        } catch (_: Exception) {}
        certs
    }

    private fun getCertFingerprint(cert: X509Certificate, algorithm: String): String {
        return try {
            val md = MessageDigest.getInstance(algorithm)
            val bytes = md.digest(cert.encoded)
            bytes.joinToString(":") { String.format("%02X", it) }
        } catch (_: Exception) {
            "N/A"
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02x", it) }
    }
}
