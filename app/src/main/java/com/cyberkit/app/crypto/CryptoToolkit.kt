package com.cyberkit.app.crypto

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CryptoToolkit {

    fun hash(input: String, algorithm: String): String {
        val md = MessageDigest.getInstance(algorithm)
        val bytes = md.digest(input.toByteArray(StandardCharsets.UTF_8))
        return bytesToHex(bytes)
    }

    fun md5(input: String): String = hash(input, "MD5")
    fun sha1(input: String): String = hash(input, "SHA-1")
    fun sha256(input: String): String = hash(input, "SHA-256")
    fun sha384(input: String): String = hash(input, "SHA-384")
    fun sha512(input: String): String = hash(input, "SHA-512")

    fun hmacSha256(key: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
        mac.init(secretKey)
        val bytes = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return bytesToHex(bytes)
    }

    fun hmacSha512(key: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA512")
        val secretKey = SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "HmacSHA512")
        mac.init(secretKey)
        val bytes = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return bytesToHex(bytes)
    }

    fun base64Encode(input: String): String {
        return Base64.getEncoder().encodeToString(input.toByteArray(StandardCharsets.UTF_8))
    }

    fun base64Decode(input: String): String {
        return try {
            val clean = input.trim().replace("\n", "").replace("\r", "")
            val bytes = Base64.getDecoder().decode(clean)
            String(bytes, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            "Invalid Base64 input"
        }
    }

    fun stringToHex(input: String): String {
        return bytesToHex(input.toByteArray(StandardCharsets.UTF_8))
    }

    fun hexToString(hex: String): String {
        return try {
            val clean = hex.replace(" ", "").removePrefix("0x")
            val bytes = ByteArray(clean.length / 2)
            for (i in bytes.indices) {
                val index = i * 2
                bytes[i] = clean.substring(index, index + 2).toInt(16).toByte()
            }
            String(bytes, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            "Invalid Hex input"
        }
    }

    fun urlEncode(input: String): String {
        return URLEncoder.encode(input, StandardCharsets.UTF_8.toString())
    }

    fun urlDecode(input: String): String {
        return try {
            URLDecoder.decode(input, StandardCharsets.UTF_8.toString())
        } catch (_: Exception) {
            "Invalid URL encoded input"
        }
    }

    fun stringToBinary(input: String): String {
        val bytes = input.toByteArray(StandardCharsets.UTF_8)
        return bytes.joinToString(" ") { b ->
            String.format("%8s", Integer.toBinaryString(b.toInt() and 0xFF)).replace(' ', '0')
        }
    }

    fun generateUuid(): String = UUID.randomUUID().toString()

    fun generateSecureRandomHex(byteCount: Int = 32): String {
        val random = SecureRandom()
        val bytes = ByteArray(byteCount.coerceIn(4, 256))
        random.nextBytes(bytes)
        return bytesToHex(bytes)
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        val hexArray = "0123456789abcdef".toCharArray()
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }
}
