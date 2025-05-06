package org.example.airplay.service

import org.example.airplay.common.MDNS_SERVICE_TYPE
import org.example.airplay.common.RTSP_PORT
import org.example.airplay.util.txtAirPlayProps
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import javax.jmdns.JmDNS
import javax.jmdns.ServiceInfo

/**
 * Utilize JmDNS to register airplay service type
 */
class BonjourServer() {
    private lateinit var jmdns: JmDNS

    fun start(deviceName: String = "AirPlayTV") {
        try {
            var ip = InetAddress.getLocalHost()
            if (ip.isLoopbackAddress) {
                for (inetAddress in InetAddress.getAllByName(ip.hostName)) {
                    if (inetAddress is Inet4Address && inetAddress.hostAddress.startsWith("192.168.")) {
                        LOGGER.info("Found ipv4 address: ${inetAddress.hostAddress}")
                        ip = inetAddress
                        break
                    }
                }
            }

            jmdns = JmDNS.create(ip)

            val serviceInfo = ServiceInfo.create(
                MDNS_SERVICE_TYPE,
                deviceName,
                RTSP_PORT,  // RTSP 监听端口
                0,
                0,
                txtAirPlayProps()
            )

            jmdns.registerService(serviceInfo)
            LOGGER.info("Bonjour service started as $deviceName on port ${RTSP_PORT}")

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
