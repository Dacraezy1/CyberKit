package com.cyberkit.app.files

import java.io.File
import java.io.InputStream
import kotlin.math.ln

object EntropyCalculator {

    /**
     * Calculates Shannon entropy (0.0 to 8.0 bits per byte).
     * Values > 7.2 typically indicate encrypted, packed, or compressed data.
     * Plaintext ASCII is typically between 3.5 and 5.5.
     */
    fun calculateEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val frequency = IntArray(256)
        for (b in bytes) {
            frequency[b.toInt() and 0xFF]++
        }

        var entropy = 0.0
        val total = bytes.size.toDouble()
        val log2 = ln(2.0)

        for (count in frequency) {
            if (count > 0) {
                val p = count / total
                entropy -= p * (ln(p) / log2)
            }
        }
        return entropy
    }

    fun calculateFileEntropy(file: File, sampleLimit: Int = 1_000_000): Double {
        if (!file.exists() || file.length() == 0L) return 0.0
        val sampleSize = minOf(file.length(), sampleLimit.toLong()).toInt()
        val buffer = ByteArray(sampleSize)
        file.inputStream().use { stream ->
            var totalRead = 0
            while (totalRead < sampleSize) {
                val read = stream.read(buffer, totalRead, sampleSize - totalRead)
                if (read == -1) break
                totalRead += read
            }
        }
        return calculateEntropy(buffer)
    }
}
