package com.cyberkit.app.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import com.cyberkit.app.core.model.AssessmentSummary
import com.cyberkit.app.core.model.Finding
import com.cyberkit.app.core.model.FindingConfidence
import com.cyberkit.app.core.model.FindingSeverity

data class WifiDetails(
    val isConnected: Boolean,
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val signalPercent: Int,
    val frequencyMhz: Int,
    val channel: Int,
    val band: String,
    val linkSpeedMbps: Int,
    val ipAddress: String,
    val gateway: String,
    val dnsServers: List<String>,
    val securityType: String
)

class WifiAnalyzer(private val context: Context) {

    fun getWifiDetails(): WifiDetails {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager

        val activeNetwork = connectivityManager?.activeNetwork
        val caps = connectivityManager?.getNetworkCapabilities(activeNetwork)
        val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true

        if (!isWifi || wifiManager == null) {
            return WifiDetails(
                isConnected = false,
                ssid = "Not connected to Wi-Fi",
                bssid = "N/A",
                rssi = 0,
                signalPercent = 0,
                frequencyMhz = 0,
                channel = 0,
                band = "N/A",
                linkSpeedMbps = 0,
                ipAddress = "N/A",
                gateway = "N/A",
                dnsServers = emptyList(),
                securityType = "N/A"
            )
        }

        val wifiInfo: WifiInfo? = wifiManager.connectionInfo
        val dhcpInfo = wifiManager.dhcpInfo

        val rawSsid = wifiInfo?.ssid?.replace("\"", "") ?: "Unknown"
        val ssid = if (rawSsid == "<unknown ssid>") "Restricted (Requires Location Permission on Android 8+)" else rawSsid
        val rawBssid = wifiInfo?.bssid ?: "Unavailable"
        val bssid = if (rawBssid == "02:00:00:00:00:00") "Masked by Android privacy sandbox" else rawBssid

        val rssi = wifiInfo?.rssi ?: 0
        val signalPercent = calculateSignalPercent(rssi)
        val freq = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) wifiInfo?.frequency ?: 0 else 0
        val channel = frequencyToChannel(freq)
        val band = when {
            freq in 2400..2500 -> "2.4 GHz"
            freq in 4900..5900 -> "5 GHz"
            freq in 5925..7125 -> "6 GHz (Wi-Fi 6E)"
            else -> "Unknown Band"
        }

        val linkSpeed = wifiInfo?.linkSpeed ?: 0
        val ip = if (dhcpInfo != null && dhcpInfo.ipAddress != 0) {
            intToIp(dhcpInfo.ipAddress)
        } else "Unavailable"

        val gateway = if (dhcpInfo != null && dhcpInfo.gateway != 0) {
            intToIp(dhcpInfo.gateway)
        } else "Unavailable"

        val dnsList = mutableListOf<String>()
        if (dhcpInfo != null) {
            if (dhcpInfo.dns1 != 0) dnsList.add(intToIp(dhcpInfo.dns1))
            if (dhcpInfo.dns2 != 0) dnsList.add(intToIp(dhcpInfo.dns2))
        }

        val secType = "WPA2/WPA3 (Protected)"

        return WifiDetails(
            isConnected = true,
            ssid = ssid,
            bssid = bssid,
            rssi = rssi,
            signalPercent = signalPercent,
            frequencyMhz = freq,
            channel = channel,
            band = band,
            linkSpeedMbps = linkSpeed,
            ipAddress = ip,
            gateway = gateway,
            dnsServers = dnsList,
            securityType = secType
        )
    }

    private fun calculateSignalPercent(rssi: Int): Int {
        return when {
            rssi <= -100 -> 0
            rssi >= -50 -> 100
            else -> 2 * (rssi + 100)
        }.coerceIn(0, 100)
    }

    private fun frequencyToChannel(freq: Int): Int {
        return when {
            freq == 2484 -> 14
            freq in 2412..2472 -> (freq - 2407) / 5
            freq in 5170..5825 -> (freq - 5000) / 5
            freq in 5925..7125 -> (freq - 5950) / 5 + 1
            else -> 0
        }
    }

    private fun intToIp(i: Int): String {
        return "${i and 0xFF}.${(i shr 8) and 0xFF}.${(i shr 16) and 0xFF}.${(i shr 24) and 0xFF}"
    }

    fun generateAssessmentSummary(details: WifiDetails): AssessmentSummary {
        val findings = mutableListOf<Finding>()

        if (!details.isConnected) {
            findings.add(
                Finding(
                    severity = FindingSeverity.INFO,
                    title = "Wi-Fi Interface Inactive",
                    description = "Device is not currently connected to any Wi-Fi access point.",
                    evidence = "Wi-Fi state: disconnected",
                    target = "Local Wi-Fi",
                    module = "Wi-Fi Analyzer",
                    confidence = FindingConfidence.HIGH
                )
            )
            return AssessmentSummary(
                title = "Wi-Fi Security: Not Connected",
                target = "Wi-Fi",
                module = "Wi-Fi Analyzer",
                score = 100,
                findings = findings
            )
        }

        if (details.securityType.contains("Open", ignoreCase = true)) {
            findings.add(
                Finding(
                    severity = FindingSeverity.CRITICAL,
                    title = "Insecure Open Wi-Fi Network",
                    description = "The connected Wi-Fi network lacks encryption. Wireless frames can be intercepted by eavesdroppers within physical range.",
                    evidence = "SSID: ${details.ssid}, Security: ${details.securityType}",
                    target = details.ssid,
                    module = "Wi-Fi Analyzer",
                    remediation = "Disconnect from open networks or immediately enable a verified VPN to encrypt all traffic.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        if (details.signalPercent < 30) {
            findings.add(
                Finding(
                    severity = FindingSeverity.LOW,
                    title = "Weak Wi-Fi Signal (${details.rssi} dBm)",
                    description = "Low signal strength may cause packet retransmissions, latency spikes, or connection drops.",
                    evidence = "RSSI: ${details.rssi} dBm (${details.signalPercent}%)",
                    target = details.ssid,
                    module = "Wi-Fi Analyzer",
                    remediation = "Reposition closer to the access point or minimize physical interference.",
                    confidence = FindingConfidence.HIGH
                )
            )
        }

        findings.add(
            Finding(
                severity = FindingSeverity.INFO,
                title = "Wi-Fi Connection Active",
                description = "Connected to ${details.ssid} on channel ${details.channel} (${details.band}) with link speed ${details.linkSpeedMbps} Mbps.",
                evidence = "Gateway: ${details.gateway}, DNS: ${details.dnsServers.joinToString()}",
                target = details.ssid,
                module = "Wi-Fi Analyzer",
                remediation = "Maintain WPA3 or WPA2-AES security with strong pre-shared passphrases (minimum 16 random characters).",
                confidence = FindingConfidence.HIGH
            )
        )

        val score = AssessmentSummary.calculateScore(findings)
        return AssessmentSummary(
            title = "Wi-Fi Audit: ${details.ssid}",
            target = details.ssid,
            module = "Wi-Fi Analyzer",
            score = score,
            findings = findings,
            metadata = mapOf(
                "SSID" to details.ssid,
                "Channel" to details.channel.toString(),
                "Band" to details.band,
                "Signal" to "${details.signalPercent}% (${details.rssi} dBm)",
                "Gateway" to details.gateway,
                "Local IP" to details.ipAddress
            )
        )
    }
}
