package org.example.airplay.service

import org.slf4j.LoggerFactory
import java.util.UUID
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

class AirPlayServer() {

    private val executor = ThreadPoolExecutor(
        5, 16,
        60L, TimeUnit.SECONDS,
        SynchronousQueue()
    )

    private lateinit var sessionManager: SessionManager
    private lateinit var bonjourServer: BonjourServer
    private lateinit var rtspServer: RTSPServer
//    private val rtcpServer = RTCPServer(executor)
//    private val videoRTPServer = VideoRTPServer(executor)
//    private val audioRTPServer = AudioRTPServer(executor)

    fun start() {
        try {
            sessionManager = SessionManager()
            bonjourServer = BonjourServer()
            rtspServer = RTSPServer(sessionManager, executor)
            rtspServer.start()
//            videoRTPServer.session(session).start()
//            videoRTPServer.session(session).start()
//            audioRTPServer.session(session).start()

//            rtcpServer.session(session).start(VIDEO_RTCP_PORT)
//            rtcpServer.start(AUDIO_RTCP_PORT)
            bonjourServer.start()

        } catch (e: Exception) {
            LOGGER.error("Start AirPlay server error: ${e.message}")

        }

    }

    fun stop() {
        try {
            bonjourServer.stop()
//            videoRTPServer.stop()
//            audioRTPServer.stop()
            rtspServer.stop()
//            rtcpServer.stop()
        } catch (e: Exception) {
            LOGGER.error("Stop AirPlay server error: ${e.message}")
        }
    }

}

private val LOGGER = LoggerFactory.getLogger(AirPlayServer::class.java)