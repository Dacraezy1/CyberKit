package com.cyberkit.app

import com.cyberkit.app.files.EntropyCalculator
import org.junit.Assert.*
import org.junit.Test

class EntropyCalculatorTest {

    @Test
    fun testZeroEntropy() {
        val emptyBytes = ByteArray(0)
        assertEquals(0.0, EntropyCalculator.calculateEntropy(emptyBytes), 0.001)

        val repeatedBytes = ByteArray(100) { 'A'.code.toByte() }
        assertEquals(0.0, EntropyCalculator.calculateEntropy(repeatedBytes), 0.001)
    }

    @Test
    fun testMaxEntropy() {
        // All 256 byte values equally represented -> entropy should equal log2(256) = 8.0 bits/byte
        val fullSpectrum = ByteArray(256) { it.toByte() }
        val entropy = EntropyCalculator.calculateEntropy(fullSpectrum)
        assertEquals(8.0, entropy, 0.001)
    }

    @Test
    fun testAsciiTextEntropy() {
        val text = "The quick brown fox jumps over the lazy dog.".toByteArray(Charsets.UTF_8)
        val entropy = EntropyCalculator.calculateEntropy(text)
        assertTrue(entropy in 4.0..5.5)
    }
}
