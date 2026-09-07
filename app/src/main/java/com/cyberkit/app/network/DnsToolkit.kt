package com.cyberkit.app.network

import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.net.InetAddress
import java.util.concurrent.TimeUnit

data class DnsRecord(
    val recordType: String,
    val name: String,
    val value: String,
    val ttl: Int
)

data class DnsAnalysisResult(
    val domain: String,
    val latencyMs: Long,
    val records: List<DnsRecord>,
    val dnssecValid: Boolean,
    val reverseDns: String = ""
)

class DnsToolkit {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    suspend fun analyzeDomain(domain: String): DnsAnalysisResult = withContext(Dispatchers.IO) {
        val cleanDomain = domain.trim().removePrefix("https://").removePrefix("http://").split("/")[0].split(":")[0]
        val startTime = System.currentTimeMillis()

        val recordTypes = listOf("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
        val foundRecords = mutableListOf<DnsRecord>()
        var dnssec = false

        // 1. First resolve native system DNS (for A/AAAA)
        try {
            val systemAddrs = InetAddress.getAllByName(cleanDomain)
            for (addr in systemAddrs) {
                val type = if (addr.hostAddress?.contains(":") == true) "AAAA" else "A"
                foundRecords.add(DnsRecord(type, cleanDomain, addr.hostAddress ?: "", 300))
            }
        } catch (_: Exception) {}

        // 2. Query DoH (Cloudflare / Google) for full record types and DNSSEC validation
        for (type in recordTypes) {
            try {
                val request = Request.Builder()
                    .url("https://cloudflare-dns.com/dns-query?name=$cleanDomain&type=$type")
                    .header("Accept", "application/dns-json")
                    .build()

                httpClient.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        val body = response.body?.string() ?: ""
                        if (body.isNotEmpty()) {
                            val json = JSONObject(body)
                            if (json.optBoolean("AD", false)) {
                                dnssec = true
                            }
                            val answers = json.optJSONArray("Answer")
                            if (answers != null) {
                                for (i in 0 until answers.length()) {
                                    val item = answers.getJSONObject(i)
                                    val data = item.optString("data", "")
                                    val ttl = item.optInt("TTL", 0)
                                    val rName = item.optString("name", cleanDomain)
                                    if (data.isNotBlank()) {
                                        foundRecords.add(DnsRecord(type, rName, data, ttl))
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        val latency = System.currentTimeMillis() - startTime

        // 3. Reverse DNS check for the primary IP
        val primaryIp = foundRecords.firstOrNull { it.recordType == "A" }?.value ?: ""
        var revDns = ""
        if (primaryIp.isNotEmpty()) {
            try {
                revDns = InetAddress.getByName(primaryIp).canonicalHostName
            } catch (_: Exception) {}
        }

        // De-duplicate records
        val distinctRecords = foundRecords.distinctBy { "${it.recordType}-${it.value}" }

        DnsAnalysisResult(
            domain = cleanDomain,
            latencyMs = latency,
            records = distinctRecords,
            dnssecValid = dnssec,
            reverseDns = revDns
        )
    }

    suspend fun reverseLookup(ip: String): String = withContext(Dispatchers.IO) {
        try {
            val addr = InetAddress.getByName(ip.trim())
            addr.canonicalHostName
        } catch (e: Exception) {
            "Reverse lookup failed: ${e.message}"
        }
    }

    fun generateAssessmentSummary(result: DnsAnalysisResult): AssessmentSummary {
        val findings = mutableListOf<Finding>()

        if (!result.dnssecValid) {
            findings.add(
                Finding(
                    severity = FindingSeverity.MEDIUM,
                    title = "DNSSEC Not Enabled or Validated",
                    description = "The DNS responses for ${result.domain} did not contain valid DNSSEC Authenticated Data (AD).",
                    evidence = "AD bit: false in DNS resolution",
                    target = result.domain,
                    module = "DNS Toolkit",
                    remediation = "Enable DNSSEC signing on your domain registrar and DNS authoritative nameserver to prevent DNS spoofing and cache poisoning.",
                    confidence = FindingConfidence.HIGH
                )
            )
        } else {
            findings.add(
                Finding(
                    severity = FindingSeverity.INFO,
                    title = "DNSSEC Authenticated Data Verified",
                    description = "Domain records are cryptographically signed with valid DNSSEC signatures.",
                    evidence = "AD bit verified true",
                    target = result.domain,
                    module = "DNS Toolkit",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        val txtRecords = result.records.filter { it.recordType == "TXT" }.map { it.value }
        val hasSpf = txtRecords.any { it.contains("v=spf1", ignoreCase = true) }
        val hasDmarc = txtRecords.any { it.contains("v=DMARC1", ignoreCase = true) }

        if (!hasSpf) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Missing SPF (Sender Policy Framework) Record",
                    description = "No SPF TXT record was detected on ${result.domain}. Mail servers cannot verify authorized senders.",
                    evidence = "TXT records present: ${txtRecords.size}",
                    target = result.domain,
                    module = "DNS Toolkit",
                    remediation = "Configure a TXT record with 'v=spf1 ...' designating your authorized outbound mail relays.",
                    confidence = FindingConfidence.MEDIUM
                )
            )
        }

        if (result.records.none { it.recordType == "MX" }) {
            findings.add(
                Finding(
                    severity = FindingSeverity.INFO,
                    title = "No Mail Exchange (MX) Records Found",
                    description = "No MX records are configured. If this domain handles email, delivery will fail.",
                    evidence = "MX query returned 0 records",
                    target = result.domain,
                    module = "DNS Toolkit",
                    remediation = "Add MX records if email delivery is expected on this domain.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "DNS Analysis: ${result.domain}",
            target = result.domain,
            module = "DNS Toolkit",
            score = score,
            findings = findings,
            metadata = mapOf(
                "Domain" to result.domain,
                "Query Latency" to "${result.latencyMs}ms",
                "Total Records" to result.records.size.toString(),
                "DNSSEC" to if (result.dnssecValid) "Active" else "Inactive",
                "Reverse PTR" to result.reverseDns
            )
        )
    }
}
