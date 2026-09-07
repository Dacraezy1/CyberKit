package com.cyberkit.app

import com.cyberkit.app.crypto.PasswordAnalyzer
import com.cyberkit.app.crypto.PasswordStrength
import org.junit.Assert.*
import org.junit.Test

class PasswordAnalyzerTest {

    @Test
    fun testWeakPasswords() {
        val res1 = PasswordAnalyzer.analyze("123456")
        assertEquals(PasswordStrength.WEAK, res1.strength)
        assertTrue(res1.isCommonPassword)

        val res2 = PasswordAnalyzer.analyze("password")
        assertEquals(PasswordStrength.WEAK, res2.strength)
        assertTrue(res2.isCommonPassword)

        val res3 = PasswordAnalyzer.analyze("aaaa1111")
        assertEquals(PasswordStrength.WEAK, res3.strength)
        assertTrue(res3.hasRepetitions)
    }

    @Test
    fun testStrongPassword() {
        val res = PasswordAnalyzer.analyze("Xk9#mP2\$vL8!qZ4*")
        assertTrue(res.strength == PasswordStrength.STRONG || res.strength == PasswordStrength.VERY_STRONG)
        assertTrue(res.hasLowercase)
        assertTrue(res.hasUppercase)
        assertTrue(res.hasDigits)
        assertTrue(res.hasSymbols)
        assertTrue(res.entropyBits > 70.0)
        assertFalse(res.isCommonPassword)
    }

    @Test
    fun testSequentialDetection() {
        val res = PasswordAnalyzer.analyze("abcd123456")
        assertTrue(res.hasSequences)
    }
}
