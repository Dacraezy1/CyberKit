package com.cyberkit.app.terminal

import com.cyberkit.app.crypto.CryptoToolkit
import com.cyberkit.app.crypto.PasswordAnalyzer
import com.cyberkit.app.cvss.CvssCalculator
import com.cyberkit.app.cvss.CvssMetrics
import com.cyberkit.app.network.DnsToolkit
import com.cyberkit.app.network.HostDiscovery
import com.cyberkit.app.network.NetworkUtils
import com.cyberkit.app.network.PortPresets
import com.cyberkit.app.network.PortScanner
import com.cyberkit.app.network.ServiceDetection
import com.cyberkit.app.web.TlsAnalyzer
import com.cyberkit.app.web.UrlAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class CyberKitTerminalEngine {

    suspend fun executeCommand(input: String): String = withContext(Dispatchers.IO) {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return@withContext ""

        val tokens = trimmed.split("\\s+".toRegex())
        val cmd = tokens[0].lowercase()
        val args = tokens.drop(1)

        when (cmd) {
            "help" -> getHelpText()
            "clear" -> "" // Cleared by UI caller
            "netinfo" -> runNetInfo()
            "subnet" -> runSubnet(args)
            "discover" -> runDiscover(args)
            "scan", "ports" -> runScan(args)
            "service" -> runService(args)
            "dns" -> runDns(args)
            "reverse" -> runReverse(args)
            "tls" -> runTls(args)
            "url" -> runUrl(args)
            "hash" -> runHash(args)
            "base64" -> runBase64(args)
            "hex" -> runHex(args)
            "cvss" -> runCvss(args)
            "password" -> runPassword(args)
            else -> "Unknown command: '$cmd'. Type 'help' to view available CyberKit tools."
        }
    }

    private fun getHelpText(): String {
        return """
            CYBERKIT INTERACTIVE SECURITY CONSOLE
            =====================================
            Available commands:
              netinfo                   Inspect local network interfaces & IP addresses
              subnet <cidr>             Calculate network, broadcast, usable range (e.g. 192.168.1.0/24)
              discover <cidr>           Discover active hosts on authorized subnet
              scan <target> [ports]     Scan TCP ports (e.g. 'scan 192.168.1.1 22,80,443' or '1-100')
              service <target> <port>   Safe service banner grab & protocol negotiation
              dns <domain>              Query DNS records (A, AAAA, MX, NS, TXT) and DNSSEC
              reverse <ip>              Perform reverse DNS (PTR) lookup
              tls <host> [port]         Inspect TLS certificate chain & cipher negotiation
              url <url>                 Analyze URL syntax, redirect chain, and security headers
              hash <algo> <text>        Compute cryptographic hash (md5, sha1, sha256, sha512)
              base64 <enc|dec> <text>   Encode or decode Base64 string
              hex <enc|dec> <text>      Encode or decode Hex string
              cvss <vector_string>      Compute CVSS v3.1 score and severity rating
              password <text>           Analyze local password strength and entropy
              clear                     Clear console screen
        """.trimIndent()
    }

    private fun runNetInfo(): String {
        val interfaces = NetworkUtils.getAllNetworkInterfaces()
        if (interfaces.isEmpty()) return "No network interfaces found."
        val sb = StringBuilder("NETWORK INTERFACES:\n")
        for (i in interfaces) {
            val ips = (i.ipv4Addresses + i.ipv6Addresses).joinToString(", ")
            sb.append("  * ${i.name} (${i.displayName}) - Up: ${i.isUp}, Loopback: ${i.isLoopback}, MTU: ${i.mtu}\n")
            if (ips.isNotBlank()) sb.append("    IPs: $ips\n")
        }
        return sb.toString().trimEnd()
    }

    private fun runSubnet(args: List<String>): String {
        if (args.isEmpty()) return "Usage: subnet <ip/prefix> (e.g. subnet 192.168.1.0/24)"
        return try {
            val sub = NetworkUtils.calculateSubnet(args[0])
            """
                SUBNET CALCULATION: ${sub.cidrNotation}
                ----------------------------------------
                Network Address:    ${sub.networkAddress}
                Broadcast Address:  ${sub.broadcastAddress}
                Netmask:            ${sub.netmask}
                Wildcard Mask:      ${sub.wildcardMask}
                First Usable Host:  ${sub.firstUsableHost}
                Last Usable Host:   ${sub.lastUsableHost}
                Usable Hosts:       ${sub.usableHosts} / Total: ${sub.totalHosts}
            """.trimIndent()
        } catch (e: Exception) {
            "Subnet calculation error: ${e.message}"
        }
    }

    private suspend fun runDiscover(args: List<String>): String {
        if (args.isEmpty()) return "Usage: discover <cidr> (e.g. discover 192.168.1.0/24)"
        val cidr = args[0]
        val discovery = HostDiscovery()
        val hosts = discovery.discoverSubnet(cidr, timeoutMs = 800, concurrency = 25) { _, _, _ -> }
        if (hosts.isEmpty()) return "No responsive hosts discovered on $cidr."

        val sb = StringBuilder("DISCOVERED HOSTS ON $cidr (${hosts.size} active):\n")
        for (h in hosts) {
            val ports = if (h.respondingPorts.isNotEmpty()) " [Open: ${h.respondingPorts.joinToString()}]" else ""
            sb.append("  * ${h.ip.padEnd(15)} - ${h.hostname.padEnd(20)} (${h.latencyMs}ms, ${h.detectionMethod})$ports\n")
        }
        return sb.toString().trimEnd()
    }

    private suspend fun runScan(args: List<String>): String {
        if (args.isEmpty()) return "Usage: scan <target> [ports] (e.g. scan 192.168.1.1 22,80,443 or scan 192.168.1.1 1-100)"
        val target = args[0]
        val ports = if (args.size > 1) {
            NetworkUtils.parsePortRange(args[1])
        } else {
            PortPresets.TOP_20
        }

        if (ports.isEmpty()) return "Invalid port specification."
        val scanner = PortScanner()
        val results = scanner.scanPorts(target, ports, timeoutMs = 1000, concurrency = 20) { _, _, _ -> }
        val openPorts = results.filter { it.status == com.cyberkit.app.network.PortStatus.OPEN }

        val sb = StringBuilder("TCP SCAN RESULTS FOR $target (Ports scanned: ${ports.size}):\n")
        if (openPorts.isEmpty()) {
            sb.append("  No open ports found.\n")
        } else {
            sb.append("  PORT    STATUS   SERVICE     BANNER / DETAILS\n")
            sb.append("  --------------------------------------------------\n")
            for (p in openPorts) {
                val svc = p.serviceInfo?.serviceName ?: "Unknown"
                val banner = p.serviceInfo?.banner?.take(40) ?: ""
                sb.append("  ${p.port.toString().padEnd(7)} OPEN     ${svc.padEnd(11)} $banner (${p.latencyMs}ms)\n")
            }
        }
        sb.append("  Closed: ${results.count { it.status == com.cyberkit.app.network.PortStatus.CLOSED }}, Filtered: ${results.count { it.status == com.cyberkit.app.network.PortStatus.FILTERED }}")
        return sb.toString()
    }

    private fun runService(args: List<String>): String {
        if (args.size < 2) return "Usage: service <host> <port>"
        val host = args[0]
        val port = args[1].toIntOrNull() ?: return "Invalid port number."
        val info = ServiceDetection.detectService(host, port, 2000)
        return """
            SERVICE DETECTION: $host:$port
            -----------------------------
            Service:    ${info.serviceName}
            Confidence: ${info.confidence}
            Latency:    ${info.latencyMs}ms
            Banner:     ${info.banner.ifEmpty { "None" }}
        """.trimIndent()
    }

    private suspend fun runDns(args: List<String>): String {
        if (args.isEmpty()) return "Usage: dns <domain>"
        val toolkit = DnsToolkit()
        val res = toolkit.analyzeDomain(args[0])
        val sb = StringBuilder("DNS RECORDS FOR ${res.domain} (Latency: ${res.latencyMs}ms, DNSSEC: ${if (res.dnssecValid) "VALID" else "INACTIVE"}):\n")
        for (r in res.records) {
            sb.append("  ${r.recordType.padEnd(6)} ${r.name.padEnd(25)} ${r.value} (TTL ${r.ttl})\n")
        }
        if (res.reverseDns.isNotBlank()) sb.append("  PTR    ${res.reverseDns}\n")
        return sb.toString().trimEnd()
    }

    private suspend fun runReverse(args: List<String>): String {
        if (args.isEmpty()) return "Usage: reverse <ip>"
        val toolkit = DnsToolkit()
        val ptr = toolkit.reverseLookup(args[0])
        return "PTR: $ptr"
    }

    private suspend fun runTls(args: List<String>): String {
        if (args.isEmpty()) return "Usage: tls <host> [port]"
        val host = args[0]
        val port = if (args.size > 1) args[1].toIntOrNull() ?: 443 else 443
        val analyzer = TlsAnalyzer()
        val res = analyzer.analyzeTls(host, port)
        val cert = res.certificates.firstOrNull()

        return """
            TLS CERTIFICATE AUDIT: ${res.host}:${res.port}
            ------------------------------------------------
            Protocol:           ${res.protocol}
            Cipher Suite:       ${res.cipherSuite}
            System CA Trusted:  ${if (res.isTrustedBySystemCa) "YES" else "NO (${res.trustErrorMessage})"}
            Handshake Latency:  ${res.handshakeLatencyMs}ms
            Subject:            ${cert?.subject ?: "N/A"}
            Issuer:             ${cert?.issuer ?: "N/A"}
            Valid Until:        ${cert?.validTo ?: "N/A"} (${cert?.daysRemaining ?: 0} days remaining)
            Signature Alg:      ${cert?.signatureAlgorithm ?: "N/A"}
            Key Size:           ${cert?.keySizeBits ?: -1} bits (${cert?.publicKeyAlgorithm ?: "N/A"})
            SANs:               ${cert?.sans?.take(5)?.joinToString() ?: "None"}
        """.trimIndent()
    }

    private suspend fun runUrl(args: List<String>): String {
        if (args.isEmpty()) return "Usage: url <url>"
        val analyzer = UrlAnalyzer()
        val res = analyzer.analyzeUrl(args[0])
        val sb = StringBuilder("URL SECURITY ANALYSIS: ${res.syntax.rawUrl}\n")
        sb.append("  Scheme: ${res.syntax.scheme}, Host: ${res.syntax.host}, Port: ${res.syntax.port}\n")
        sb.append("  Final Status: ${res.finalStatusCode}, Redirects: ${res.redirects.size}\n")
        sb.append("  Security Headers:\n")
        for ((h, present) in res.securityHeaders) {
            val mark = if (present) "[+] PRESENT" else "[-] MISSING"
            sb.append("    $mark: $h\n")
        }
        if (res.cookies.isNotEmpty()) {
            sb.append("  Cookies (${res.cookies.size}):\n")
            for (c in res.cookies) {
                sb.append("    * ${c.name} - Secure: ${c.isSecure}, HttpOnly: ${c.isHttpOnly}, SameSite: ${c.sameSite ?: "None"}\n")
            }
        }
        return sb.toString().trimEnd()
    }

    private fun runHash(args: List<String>): String {
        if (args.size < 2) return "Usage: hash <md5|sha1|sha256|sha512> <text>"
        val algo = args[0].lowercase()
        val text = args.drop(1).joinToString(" ")
        return when (algo) {
            "md5" -> "MD5:    " + CryptoToolkit.md5(text)
            "sha1" -> "SHA-1:  " + CryptoToolkit.sha1(text)
            "sha256" -> "SHA-256: " + CryptoToolkit.sha256(text)
            "sha512" -> "SHA-512: " + CryptoToolkit.sha512(text)
            else -> "Unsupported algorithm: $algo. Use md5, sha1, sha256, or sha512."
        }
    }

    private fun runBase64(args: List<String>): String {
        if (args.size < 2) return "Usage: base64 <encode|decode> <text>"
        val op = args[0].lowercase()
        val text = args.drop(1).joinToString(" ")
        return if (op == "encode" || op == "enc") {
            CryptoToolkit.base64Encode(text)
        } else {
            CryptoToolkit.base64Decode(text)
        }
    }

    private fun runHex(args: List<String>): String {
        if (args.size < 2) return "Usage: hex <encode|decode> <text>"
        val op = args[0].lowercase()
        val text = args.drop(1).joinToString(" ")
        return if (op == "encode" || op == "enc") {
            CryptoToolkit.stringToHex(text)
        } else {
            CryptoToolkit.hexToString(text)
        }
    }

    private fun runCvss(args: List<String>): String {
        if (args.isEmpty()) return "Usage: cvss <vector_string> (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
        val vec = args[0]
        val parts = vec.removePrefix("CVSS:3.1/").split("/")
        var metrics = CvssMetrics()
        for (part in parts) {
            val kv = part.split(":")
            if (kv.size == 2) {
                val k = kv[0].uppercase()
                val v = kv[1].uppercase()
                metrics = when (k) {
                    "AV" -> metrics.copy(attackVector = v)
                    "AC" -> metrics.copy(attackComplexity = v)
                    "PR" -> metrics.copy(privilegesRequired = v)
                    "UI" -> metrics.copy(userInteraction = v)
                    "S" -> metrics.copy(scope = v)
                    "C" -> metrics.copy(confidentiality = v)
                    "I" -> metrics.copy(integrity = v)
                    "A" -> metrics.copy(availability = v)
                    else -> metrics
                }
            }
        }
        val result = CvssCalculator.calculate(metrics)
        return """
            CVSS v3.1 EVALUATION
            --------------------
            Base Score:     ${result.baseScore} / 10.0
            Severity:       ${result.severity}
            Vector:         ${result.vectorString}
            Impact Subscore: ${result.impactSubScore}
            Exploitability: ${result.exploitabilitySubScore}
            Summary:        ${result.explanation}
        """.trimIndent()
    }

    private fun runPassword(args: List<String>): String {
        if (args.isEmpty()) return "Usage: password <string>"
        val pwd = args.joinToString(" ")
        val res = PasswordAnalyzer.analyze(pwd)
        return """
            PASSWORD SECURITY ANALYSIS (100% Local)
            ---------------------------------------
            Strength:           ${res.strength} (Score: ${res.score}/100)
            Length:             ${res.length} characters
            Shannon Entropy:    ${String.format("%.1f", res.entropyBits)} bits
            Estimated Crack Time: ${res.estimatedCrackTime}
            Recommendations:
            ${res.recommendations.joinToString("\n") { "  * $it" }}
        """.trimIndent()
    }
}
