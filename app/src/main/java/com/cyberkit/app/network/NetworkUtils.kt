package com.cyberkit.app.network

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import kotlin.math.pow

data class SubnetInfo(
    val ip: String,
    val prefixLength: Int,
    val networkAddress: String,
    val broadcastAddress: String,
    val netmask: String,
    val wildcardMask: String,
    val firstUsableHost: String,
    val lastUsableHost: String,
    val totalHosts: Long,
    val usableHosts: Long,
    val cidrNotation: String
)

data class InterfaceDetail(
    val name: String,
    val displayName: String,
    val mtu: Int,
    val isUp: Boolean,
    val isLoopback: Boolean,
    val macAddress: String,
    val ipv4Addresses: List<String>,
    val ipv6Addresses: List<String>
)

object NetworkUtils {

    fun isValidIpv4(ip: String): Boolean {
        val parts = ip.trim().split(".")
        if (parts.size != 4) return false
        return parts.all { part ->
            val num = part.toIntOrNull() ?: return false
            num in 0..255 && (part == "0" || !part.startsWith("0"))
        }
    }

    fun isValidIpv6(ip: String): Boolean {
        return try {
            val addr = InetAddress.getByName(ip.trim())
            addr is Inet6Address
        } catch (_: Exception) {
            false
        }
    }

    fun isValidPort(port: Int): Boolean = port in 1..65535

    fun parsePortRange(input: String): List<Int> {
        val ports = mutableSetOf<Int>()
        val segments = input.split(",").map { it.trim() }
        for (segment in segments) {
            if (segment.contains("-")) {
                val bounds = segment.split("-").map { it.trim().toIntOrNull() }
                if (bounds.size == 2 && bounds[0] != null && bounds[1] != null) {
                    val start = bounds[0]!!.coerceIn(1, 65535)
                    val end = bounds[1]!!.coerceIn(1, 65535)
                    val min = minOf(start, end)
                    val max = maxOf(start, end)
                    for (p in min..max) {
                        ports.add(p)
                    }
                }
            } else {
                val p = segment.toIntOrNull()
                if (p != null && isValidPort(p)) {
                    ports.add(p)
                }
            }
        }
        return ports.sorted()
    }

    fun ipToLong(ip: String): Long {
        val parts = ip.split(".").map { it.toLong() }
        return (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
    }

    fun longToIp(value: Long): String {
        return "${(value shr 24) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 8) and 0xFF}.${value and 0xFF}"
    }

    fun ipToHex(ip: String): String {
        val l = ipToLong(ip)
        return "0x" + String.format("%08X", l)
    }

    fun ipToBinary(ip: String): String {
        return ip.split(".").joinToString(".") { part ->
            String.format("%8s", Integer.toBinaryString(part.toInt())).replace(' ', '0')
        }
    }

    fun calculateSubnet(cidr: String): SubnetInfo {
        val parts = cidr.trim().split("/")
        val ip = parts[0]
        val prefix = if (parts.size > 1) parts[1].toIntOrNull() ?: 24 else 24
        val clampedPrefix = prefix.coerceIn(0, 32)

        val ipLong = ipToLong(ip)
        val maskLong = if (clampedPrefix == 0) 0L else (0xFFFFFFFFL shl (32 - clampedPrefix)) and 0xFFFFFFFFL
        val wildcardLong = maskLong.inv() and 0xFFFFFFFFL
        val networkLong = ipLong and maskLong
        val broadcastLong = networkLong or wildcardLong

        val totalHosts = (2.0.pow((32 - clampedPrefix).toDouble())).toLong()
        val usableHosts = if (clampedPrefix >= 31) {
            if (clampedPrefix == 31) 2L else 1L
        } else {
            (totalHosts - 2).coerceAtLeast(0)
        }

        val firstUsable = if (clampedPrefix >= 31) networkLong else networkLong + 1
        val lastUsable = if (clampedPrefix >= 31) broadcastLong else (broadcastLong - 1).coerceAtLeast(firstUsable)

        return SubnetInfo(
            ip = ip,
            prefixLength = clampedPrefix,
            networkAddress = longToIp(networkLong),
            broadcastAddress = longToIp(broadcastLong),
            netmask = longToIp(maskLong),
            wildcardMask = longToIp(wildcardLong),
            firstUsableHost = longToIp(firstUsable),
            lastUsableHost = longToIp(lastUsable),
            totalHosts = totalHosts,
            usableHosts = usableHosts,
            cidrNotation = "${longToIp(networkLong)}/$clampedPrefix"
        )
    }

    fun getAllNetworkInterfaces(): List<InterfaceDetail> {
        val result = mutableListOf<InterfaceDetail>()
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return emptyList()
            for (intf in interfaces) {
                val ipv4List = mutableListOf<String>()
                val ipv6List = mutableListOf<String>()
                for (addr in intf.inetAddresses) {
                    if (addr is Inet4Address) {
                        ipv4List.add(addr.hostAddress ?: "")
                    } else if (addr is Inet6Address) {
                        ipv6List.add(addr.hostAddress?.split("%")?.get(0) ?: "")
                    }
                }

                val mac = try {
                    val hardware = intf.hardwareAddress
                    if (hardware != null) {
                        hardware.joinToString(":") { String.format("%02X", it) }
                    } else "Unavailable (Restricted on modern Android)"
                } catch (_: Exception) {
                    "Unavailable"
                }

                result.add(
                    InterfaceDetail(
                        name = intf.name ?: "unknown",
                        displayName = intf.displayName ?: intf.name ?: "",
                        mtu = try { intf.mtu } catch (_: Exception) { -1 },
                        isUp = try { intf.isUp } catch (_: Exception) { false },
                        isLoopback = try { intf.isLoopback } catch (_: Exception) { false },
                        macAddress = mac,
                        ipv4Addresses = ipv4List,
                        ipv6Addresses = ipv6List
                    )
                )
            }
        } catch (_: Exception) {}
        return result
    }

    fun measureTcpLatency(host: String, port: Int = 80, timeoutMs: Int = 2000): Long {
        val startTime = System.currentTimeMillis()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                System.currentTimeMillis() - startTime
            }
        } catch (_: Exception) {
            -1L
        }
    }
}
