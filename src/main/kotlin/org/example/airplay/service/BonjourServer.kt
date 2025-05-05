package org.example.airplay.service

import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import javax.jmdns.JmDNS
import javax.jmdns.ServiceInfo

class BonjourServer() {
    private lateinit var jmdns: JmDNS

    fun start(deviceName: String = "AirPlayTV") {
        try {
            var ip = InetAddress.getByName("192.168.0.97")
//            if (ip.isLoopbackAddress) {
//                for (inetAddress in InetAddress.getAllByName(ip.hostName)) {
//                    if (inetAddress is Inet4Address && inetAddress.hostAddress.startsWith("192.168.")) {
//                        LOGGER.info("Found ipv4 address: ${inetAddress.hostAddress}")
//                        ip = inetAddress
//                        break
//                    }
//                }
//            }

            jmdns = JmDNS.create(ip)

            val props = mapOf(
                "deviceid" to "02:11:32:AC:45:00",
                "features" to "0x5A7FFEE6",
                "flags" to "0x4",
                "model" to "AppleTV2,1",
                "pi" to "2e388006-13ba-4041-9a67-25dd4a43d536",
                "srcvers" to "220.68",
                "vv" to "2"
            )

            val serviceInfo = ServiceInfo.create(
                "_airplay._tcp.local.",
                deviceName,
                RTSP_PORT,  // RTSP 监听端口
                0,
                0,
                props
            )

            jmdns.registerService(serviceInfo)
            LOGGER.info("Bonjour service started as $deviceName on port $RTSP_PORT")

        } catch (e: Exception) {
            LOGGER.error("Bonjour error: ${e.message}")
        }
    }

    fun stop() {
        try {
            jmdns.unregisterAllServices()
            jmdns.close()
            LOGGER.info("Bonjour service stopped")
        } catch (e: Exception) {
            LOGGER.error("Error stopping Bonjour: ${e.message}")
        }
    }
}

private val LOGGER = LoggerFactory.getLogger(BonjourServer::class.java)
