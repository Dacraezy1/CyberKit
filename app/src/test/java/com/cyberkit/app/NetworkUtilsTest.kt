package com.cyberkit.app

import com.cyberkit.app.network.NetworkUtils
import org.junit.Assert.*
import org.junit.Test

class NetworkUtilsTest {

    @Test
    fun testIpv4Validation() {
        assertTrue(NetworkUtils.isValidIpv4("192.168.1.1"))
        assertTrue(NetworkUtils.isValidIpv4("10.0.0.1"))
        assertTrue(NetworkUtils.isValidIpv4("0.0.0.0"))
        assertTrue(NetworkUtils.isValidIpv4("255.255.255.255"))

        assertFalse(NetworkUtils.isValidIpv4("256.0.0.1"))
        assertFalse(NetworkUtils.isValidIpv4("192.168.1"))
        assertFalse(NetworkUtils.isValidIpv4("192.168.1.1.1"))
        assertFalse(NetworkUtils.isValidIpv4("abc.def.ghi.jkl"))
        assertFalse(NetworkUtils.isValidIpv4("192.168.01.1")) // Leading zero
    }

    @Test
    fun testPortRangeParsing() {
        val ports = NetworkUtils.parsePortRange("80, 443, 20-23, 8080")
        val expected = listOf(20, 21, 22, 23, 80, 443, 8080)
        assertEquals(expected, ports)

        val singlePort = NetworkUtils.parsePortRange("22")
        assertEquals(listOf(22), singlePort)

        val invalidFiltered = NetworkUtils.parsePortRange("80, 99999, -5, abc, 443")
        assertEquals(listOf(80, 443), invalidFiltered)
    }

    @Test
    fun testIpConversions() {
        val ip = "192.168.1.1"
        val ipLong = NetworkUtils.ipToLong(ip)
        assertEquals(3232235777L, ipLong)
        assertEquals(ip, NetworkUtils.longToIp(ipLong))
        assertEquals("0xC0A80101", NetworkUtils.ipToHex(ip))
        assertEquals("11000000.10101000.00000001.00000001", NetworkUtils.ipToBinary(ip))
    }

    @Test
    fun testSubnetCalculationCidr24() {
        val sub = NetworkUtils.calculateSubnet("192.168.1.105/24")
        assertEquals("192.168.1.0", sub.networkAddress)
        assertEquals("192.168.1.255", sub.broadcastAddress)
        assertEquals("255.255.255.0", sub.netmask)
        assertEquals("0.0.0.255", sub.wildcardMask)
        assertEquals("192.168.1.1", sub.firstUsableHost)
        assertEquals("192.168.1.254", sub.lastUsableHost)
        assertEquals(256L, sub.totalHosts)
        assertEquals(254L, sub.usableHosts)
    }

    @Test
    fun testSubnetCalculationCidr26() {
        val sub = NetworkUtils.calculateSubnet("10.0.0.75/26")
        assertEquals("10.0.0.64", sub.networkAddress)
        assertEquals("10.0.0.127", sub.broadcastAddress)
        assertEquals("255.255.255.192", sub.netmask)
        assertEquals("10.0.0.65", sub.firstUsableHost)
        assertEquals("10.0.0.126", sub.lastUsableHost)
        assertEquals(64L, sub.totalHosts)
        assertEquals(62L, sub.usableHosts)
    }
}
