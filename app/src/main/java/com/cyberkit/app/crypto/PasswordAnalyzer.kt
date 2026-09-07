package com.cyberkit.app.crypto

import kotlin.math.ln
import kotlin.math.log2
import kotlin.math.pow

enum class PasswordStrength {
    WEAK,
    FAIR,
    STRONG,
    VERY_STRONG
}

data class PasswordAnalysisResult(
    val length: Int,
    val entropyBits: Double,
    val score: Int, // 0 - 100
    val strength: PasswordStrength,
    val estimatedCrackTime: String,
    val hasLowercase: Boolean,
    val hasUppercase: Boolean,
    val hasDigits: Boolean,
    val hasSymbols: Boolean,
    val hasRepetitions: Boolean,
    val hasSequences: Boolean,
    val isCommonPassword: Boolean,
    val recommendations: List<String>
)

object PasswordAnalyzer {

    private val TOP_COMMON_PASSWORDS = setOf(
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
        "1234567", "dragon", "welcome", "ninja", "admin", "root", "toor", "pass123", "secret",
        "master", "letmein", "sunshine", "iloveyou", "princess", "football", "baseball"
    )

    fun analyze(password: String): PasswordAnalysisResult {
        if (password.isEmpty()) {
            return PasswordAnalysisResult(
                length = 0,
                entropyBits = 0.0,
                score = 0,
                strength = PasswordStrength.WEAK,
                estimatedCrackTime = "Instantaneous",
                hasLowercase = false,
                hasUppercase = false,
                hasDigits = false,
                hasSymbols = false,
                hasRepetitions = false,
                hasSequences = false,
                isCommonPassword = false,
                recommendations = listOf("Enter a password to evaluate strength.")
            )
        }

        val len = password.length
        val hasLower = password.any { it.isLowerCase() }
        val hasUpper = password.any { it.isUpperCase() }
        val hasDigit = password.any { it.isDigit() }
        val hasSymbol = password.any { !it.isLetterOrDigit() }

        var poolSize = 0
        if (hasLower) poolSize += 26
        if (hasUpper) poolSize += 26
        if (hasDigit) poolSize += 10
        if (hasSymbol) poolSize += 33

        // Shannon entropy estimate
        val entropy = if (poolSize > 0) len * log2(poolSize.toDouble()) else 0.0

        // Repetition check (e.g. "aaaa" or "1111")
        val hasRep = Regex("(.)\\1{2,}").containsMatchIn(password)

        // Sequential check (e.g. "1234", "abcd", "qwerty")
        val lowerPass = password.lowercase()
        val sequences = listOf("1234", "2345", "3456", "4567", "5678", "6789", "abcd", "bcde", "cdef", "defg", "qwerty", "asdf")
        val hasSeq = sequences.any { lowerPass.contains(it) }

        val isCommon = TOP_COMMON_PASSWORDS.contains(lowerPass)

        val recommendations = mutableListOf<String>()
        if (len < 12) recommendations.add("Increase password length to at least 12–16 characters.")
        if (!hasLower) recommendations.add("Add lowercase letters (a–z).")
        if (!hasUpper) recommendations.add("Add uppercase letters (A–Z).")
        if (!hasDigit) recommendations.add("Add numerical digits (0–9).")
        if (!hasSymbol) recommendations.add("Add special symbols (!@#$%^&*).")
        if (hasRep) recommendations.add("Avoid repeating identical characters consecutively.")
        if (hasSeq) recommendations.add("Avoid sequential keys or common keyboard runs (e.g. '1234', 'qwerty').")
        if (isCommon) recommendations.add("This is a known commonly breached password. Choose a unique passphrase.")

        var rawScore = (entropy * 1.2).toInt().coerceIn(0, 100)
        if (len < 8) rawScore = rawScore.coerceAtMost(25)
        if (isCommon) rawScore = 5
        if (hasRep) rawScore = (rawScore - 15).coerceAtLeast(10)
        if (hasSeq) rawScore = (rawScore - 15).coerceAtLeast(10)

        val strength = when {
            rawScore >= 80 -> PasswordStrength.VERY_STRONG
            rawScore >= 60 -> PasswordStrength.STRONG
            rawScore >= 35 -> PasswordStrength.FAIR
            else -> PasswordStrength.WEAK
        }

        val crackTime = estimateCrackTime(entropy)

        return PasswordAnalysisResult(
            length = len,
            entropyBits = entropy,
            score = rawScore,
            strength = strength,
            estimatedCrackTime = crackTime,
            hasLowercase = hasLower,
            hasUppercase = hasUpper,
            hasDigits = hasDigit,
            hasSymbols = hasSymbol,
            hasRepetitions = hasRep,
            hasSequences = hasSeq,
            isCommonPassword = isCommon,
            recommendations = recommendations
        )
    }

    private fun estimateCrackTime(entropy: Double): String {
        // Assuming 10 billion (1e10) offline guesses/second (modern GPU cluster)
        val guesses = 2.0.pow(entropy)
        val seconds = guesses / 1e10

        return when {
            seconds < 1 -> "Instant (sub-second)"
            seconds < 60 -> "${seconds.toInt()} seconds"
            seconds < 3600 -> "${(seconds / 60).toInt()} minutes"
            seconds < 86400 -> "${(seconds / 3600).toInt()} hours"
            seconds < 86400.0 * 365.0 -> "${(seconds / 86400).toInt()} days"
            seconds < 86400.0 * 365.0 * 1000.0 -> "${(seconds / (86400.0 * 365.0)).toLong()} years"
            else -> "Centuries / Computationally Infeasible"
        }
    }
}
