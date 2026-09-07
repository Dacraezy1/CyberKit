package com.cyberkit.app

import com.cyberkit.app.files.SecretScanner
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import kotlinx.coroutines.runBlocking
import java.io.File

class SecretScannerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun testDetectAwsKey() = runBlocking {
        val file = tempFolder.newFile("config.env")
        file.writeText("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nREGION=us-east-1\n")

        val matches = SecretScanner.scanTextFile(file)
        assertEquals(1, matches.size)
        assertEquals("AWS Access Key ID", matches[0].ruleName)
        assertEquals(1, matches[0].lineNumber)
        assertTrue(matches[0].maskedSnippet.startsWith("AKIA"))
    }

    @Test
    fun testDetectGithubToken() = runBlocking {
        val file = tempFolder.newFile("auth.json")
        file.writeText("{\n  \"token\": \"ghp_1234567890abcdefghijklmnopqrstuvwxyzAB\"\n}")

        val matches = SecretScanner.scanTextFile(file)
        assertEquals(1, matches.size)
        assertEquals("GitHub Personal Access Token", matches[0].ruleName)
        assertEquals(2, matches[0].lineNumber)
    }

    @Test
    fun testDetectPrivateKeyHeader() = runBlocking {
        val file = tempFolder.newFile("server.key")
        file.writeText("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n")

        val matches = SecretScanner.scanTextFile(file)
        assertEquals(1, matches.size)
        assertEquals("RSA/EC Private Key Header", matches[0].ruleName)
        assertEquals(1, matches[0].lineNumber)
    }
}
