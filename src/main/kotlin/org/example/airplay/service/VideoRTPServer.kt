//package org.example.airplay.service
//
//import android.media.MediaCodec
//import android.media.MediaFormat
//import android.os.SystemClock
//import android.view.Surface
//import com.example.airplay.utils.LogCollector
//import java.net.DatagramPacket
//import java.net.DatagramSocket
//import java.nio.ByteBuffer
//import java.util.TreeMap
//import java.util.concurrent.Executor
//
//
//class VideoRTPServer(private val executor: Executor) {
//    private lateinit var session: AirPlaySession
//    private lateinit var sps: ByteArray
//    private lateinit var pps: ByteArray
//    private lateinit var videoDecoder: MediaCodec
//    private var lastSequenceNumber = -1
//    private val frameBuffer = TreeMap<Int, ByteArray>()
//
//    fun session(session: AirPlaySession): VideoRTPServer {
//        this.session = session
//        return this
//    }
//
//    fun start(surface: Surface) {
//        executor.execute {
//            try {
//                val socket = DatagramSocket(VIDEO_RTP_PORT)
//                val buffer = ByteArray(2048)
//                LogCollector.log("RTP listener started on UDP port $VIDEO_RTP_PORT")
//
//                while (session.isRTSPStarted()) {
//                    val packet = DatagramPacket(buffer, buffer.size)
//                    socket.receive(packet)
//                    val data = packet.data.copyOf(packet.length)
//
//                    if (packet.length < 14) continue
//
//                    val seq = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
//                    val timestamp =
//                        ((data[4].toLong() and 0xFF) shl 24) or ((data[5].toLong() and 0xFF) shl 16) or ((data[6].toLong() and 0xFF) shl 8) or (data[7].toLong() and 0xFF)
//                    val nalType = data[12].toInt() and 0x1F
//                    val nalu = data.copyOfRange(12, packet.length)
//
//                    when (nalType) {
//                        7 -> {
//                            sps = prependStartCode(nalu)
//                            LogCollector.log("Received SPS")
//                        }
//
//                        8 -> {
//                            pps = prependStartCode(nalu)
//                            LogCollector.log("Received PPS")
//                        }
//
//                        else -> {
//                            if (!session.isVideoDecoderStarted()) {
//                                startVideoDecoder(surface)
//                            }
//
//                            if (session.getBaseTimestampUs() < 0) {
//                                session.setBaseTimestampUs(timestamp * 1000L)
//                                session.setBaseMonoTimeUs(SystemClock.elapsedRealtimeNanos() / 1000)
//                            }
//                            val ptsUs = session.getPresentationTimeUs(timestamp)
//
//                            if (isNextSequence(seq)) {
//                                decodeNalu(nalu, ptsUs)
//                                lastSequenceNumber = seq
//
//                                while (frameBuffer.containsKey(lastSequenceNumber + 1)) {
//                                    val next =
//                                        frameBuffer.remove(lastSequenceNumber + 1) ?: continue
//                                    decodeNalu(next, ptsUs)
//                                    lastSequenceNumber += 1
//                                }
//                            } else if (seq > lastSequenceNumber + 1) {
//                                frameBuffer[seq] = nalu
//                            }
//                        }
//                    }
//                }
//                socket.close()
//            } catch (e: Exception) {
//                LogCollector.log("RTP listener error: ${e.message}")
//            }
//        }
//    }
//
//    fun stop() {
//        try {
//            session.setVideoDecoderStarted(false)
//            videoDecoder.stop()
//            videoDecoder.release()
//            LogCollector.log("Video RTP server stopped.")
//        } catch (e: Exception) {
//            LogCollector.log("Error stopping Video RTP server: ${e.message}")
//        }
//    }
//
//    private fun startVideoDecoder(surface: Surface) {
//
//        val csd0 = ByteBuffer.wrap(sps)
//        val csd1 = ByteBuffer.wrap(pps)
//        val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, 1920, 1080)
//        format.setByteBuffer("csd-0", csd0)
//        format.setByteBuffer("csd-1", csd1)
//
//        videoDecoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
//        videoDecoder.configure(format, surface, null, 0)
//        videoDecoder.start()
//
//        LogCollector.log("Decoder initialized with SPS/PPS")
//        session.setVideoDecoderStarted(true)
//    }
//
//    private fun prependStartCode(nalu: ByteArray): ByteArray {
//        val startCode = byteArrayOf(0x00, 0x00, 0x00, 0x01)
//        return startCode + nalu
//    }
//
//    private fun isNextSequence(current: Int): Boolean {
//        return lastSequenceNumber == -1 || current == (lastSequenceNumber + 1) % 65536
//    }
//
//    private fun decodeNalu(nalu: ByteArray, ptsUs: Long) {
//        val frame = prependStartCode(nalu)
//        val index = videoDecoder.dequeueInputBuffer(10000)
//        if (index >= 0) {
//            val inputBuffer = videoDecoder.getInputBuffer(index)
//            inputBuffer?.clear()
//            inputBuffer?.put(frame)
//            videoDecoder.queueInputBuffer(index, 0, frame.size, ptsUs, 0)
//        }
//
//        val bufferInfo = MediaCodec.BufferInfo()
//        var outIndex = videoDecoder.dequeueOutputBuffer(bufferInfo, 10000)
//        while (outIndex >= 0) {
//            videoDecoder.releaseOutputBuffer(outIndex, true)
//            outIndex = videoDecoder.dequeueOutputBuffer(bufferInfo, 0)
//        }
//    }
//}