package com.cyberkit.app

import com.cyberkit.app.crypto.CryptoToolkit
import org.junit.Assert.*
import org.junit.Test

class CryptoToolkitTest {

    @Test
    fun testMd5() {
        val result = CryptoToolkit.md5("hello")
        assertEquals("5d41402abc4b2a76b9719d911017c592", result)
    }

    @Test
    fun testSha1() {
        val result = CryptoToolkit.sha1("hello")
        assertEquals("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", result)
    }

    @Test
    fun testSha256() {
        val result = CryptoToolkit.sha256("hello")
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", result)
    }

    @Test
    fun testSha512() {
        val result = CryptoToolkit.sha512("hello")
        assertTrue(result.startsWith("9b71d224bd62f3785d96d46ad3ea3d73319bf521"))
        assertEquals(128, result.length)
    }

    @Test
    fun testHmacSha256() {
        val hmac = CryptoToolkit.hmacSha256("key123", "data456")
        assertNotNull(hmac)
        assertEquals(64, hmac.length)
    }

    @Test
    fun testHexConversions() {
        val input = "CyberKit"
        val hex = CryptoToolkit.stringToHex(input)
        val decoded = CryptoToolkit.hexToString(hex)
        assertEquals(input, decoded)
    }

    @Test
    fun testUrlEncoding() {
        val raw = "test param with spaces & symbols=true"
        val encoded = CryptoToolkit.urlEncode(raw)
        val decoded = CryptoToolkit.urlDecode(encoded)
        assertEquals(raw, decoded)
    }

    @Test
    fun testUuidGeneration() {
        val uuid = CryptoToolkit.generateUuid()
        assertTrue(uuid.matches(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")))
    }
}
