package org.example.airplay.service

import org.example.airplay.common.Constants
import org.example.airplay.util.PropertyHelper
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

    fun start() {
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
                Constants.MDNS_SERVICE_TYPE,
                Constants.NAME,
                Constants.RTSP_PORT,  // RTSP 监听端口
                0,
                0,
                PropertyHelper.txtAirPlayProps()
            )

            jmdns.registerService(serviceInfo)
            LOGGER.info("Bonjour service started as ${Constants.NAME} on port ${Constants.RTSP_PORT}")

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
