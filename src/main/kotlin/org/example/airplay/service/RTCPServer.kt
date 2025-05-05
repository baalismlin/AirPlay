//package org.example.airplay.service
//
//import com.example.airplay.utils.LogCollector
//import java.net.DatagramPacket
//import java.net.DatagramSocket
//import java.util.concurrent.Executor
//
//class RTCPServer(private val executor: Executor) {
//    private lateinit var session: AirPlaySession
//
//    fun session(session: AirPlaySession): RTCPServer {
//        this.session = session
//        return this
//    }
//
//    fun start(port: Int) {
//        executor.execute {
//            try {
//                val socket = DatagramSocket(port)
//                val buffer = ByteArray(1500)
//                LogCollector.log("RTCP listener started on port $port")
//
//                while (session.isRTSPStarted()) {
//                    val packet = DatagramPacket(buffer, buffer.size)
//                    socket.receive(packet)
//
//                    val data = packet.data.copyOf(packet.length)
//                    if (data.isNotEmpty() && (data[0].toInt() shr 6) == 2) {
//                        val rtcpType = data[1].toInt() and 0xFF
//                        if (rtcpType == 200) {  // Sender Report (SR)
//                            LogCollector.log("Received RTCP SR")
//
//                            // Respond with Receiver Report (RR)
//                            val rr = buildRtcpReceiverReport()
//                            val response = DatagramPacket(rr, rr.size, packet.address, packet.port)
//                            socket.send(response)
//                            LogCollector.log("Sent RTCP RR")
//                        }
//                    }
//                }
//                socket.close()
//            } catch (e: Exception) {
//                LogCollector.log("RTCP error on port $port: ${e.message}")
//            }
//        }
//    }
//
//    fun stop() {
//
//    }
//
//    private fun buildRtcpReceiverReport(): ByteArray {
//        val buffer = ByteArray(32)
//        buffer[0] = 0x80.toByte() // Version 2, no padding, 0 report blocks
//        buffer[1] = 201.toByte()  // RTCP RR
//        buffer[2] = 0x00
//        buffer[3] = 0x07          // length = 7 words (32 bytes)
//
//        // SSRC of receiver (random)
//        val ssrc = 0x12345678
//        buffer[4] = ((ssrc shr 24) and 0xFF).toByte()
//        buffer[5] = ((ssrc shr 16) and 0xFF).toByte()
//        buffer[6] = ((ssrc shr 8) and 0xFF).toByte()
//        buffer[7] = (ssrc and 0xFF).toByte()
//
//        // 余下字节保留为0
//        return buffer
//    }
//}