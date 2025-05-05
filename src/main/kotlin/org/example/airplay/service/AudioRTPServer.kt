//package org.example.airplay.service
//
//import android.media.AudioFormat
//import android.media.AudioManager
//import android.media.AudioTrack
//import android.media.MediaCodec
//import android.media.MediaCodecInfo
//import android.media.MediaFormat
//import android.os.SystemClock
//import com.example.airplay.utils.LogCollector
//import java.net.DatagramPacket
//import java.net.DatagramSocket
//import java.util.concurrent.Executor
//
//class AudioRTPServer(private val executor: Executor, ) {
//    private lateinit var session: AirPlaySession
//    private lateinit var audioDecoder: MediaCodec
//    private lateinit var audioTrack: AudioTrack
//
//    fun session(session: AirPlaySession): AudioRTPServer {
//        this.session = session
//        return this
//    }
//
//    fun start() {
//        executor.execute {
//            try {
//                val socket = DatagramSocket(AUDIO_RTP_PORT)
//                val buffer = ByteArray(2048)
//                LogCollector.log("RTP audio listener started on UDP port $AUDIO_RTP_PORT")
//
//                while (session.isRTSPStarted()) {
//                    val packet = DatagramPacket(buffer, buffer.size)
//                    socket.receive(packet)
//                    val data = packet.data.copyOf(packet.length)
//
//                    val payloadType = data[1].toInt() and 0x7F
//                    val timestamp =
//                        ((data[4].toLong() and 0xFF) shl 24) or ((data[5].toLong() and 0xFF) shl 16) or ((data[6].toLong() and 0xFF) shl 8) or (data[7].toLong() and 0xFF)
//                    val audioData = data.copyOfRange(12, data.size)
//
//                    when (payloadType) {
//                        96 -> { // 96 is commonly dynamic AAC
//                            if (!session.isAudioDecoderStarted()) startAudioDecoder()
//                            decodeAac(audioData, timestamp)
//                        }
//
//                        97 -> {
//                            // example: ALAC (if we later support it)
//                            LogCollector.log("ALAC payload type detected")
//                        }
//
//                        else -> {
//                            LogCollector.log("Unknown audio payload type: $payloadType")
//                        }
//                    }
//
//                }
//                socket.close()
//            } catch (e: Exception) {
//                LogCollector.log("RTP audio error: ${e.message}")
//            }
//        }
//    }
//
//    fun stop() {
//
//    }
//
//    private fun startAudioDecoder() {
//        try {
//            val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_AAC, AUDIO_SAMPLE_RATE, 2)
//            format.setInteger(MediaFormat.KEY_IS_ADTS, 1)
//            format.setInteger(
//                MediaFormat.KEY_AAC_PROFILE,
//                MediaCodecInfo.CodecProfileLevel.AACObjectLC
//            )
//            format.setInteger(MediaFormat.KEY_CHANNEL_MASK, AudioFormat.CHANNEL_OUT_STEREO)
//
//            audioDecoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_AAC)
//            audioDecoder.configure(format, null, null, 0)
//            audioDecoder.start()
//
//            val minBufferSize = AudioTrack.getMinBufferSize(
//                AUDIO_SAMPLE_RATE,
//                AudioFormat.CHANNEL_OUT_STEREO,
//                AudioFormat.ENCODING_PCM_16BIT
//            )
//            audioTrack = AudioTrack(
//                AudioManager.STREAM_MUSIC,
//                AUDIO_SAMPLE_RATE,
//                AudioFormat.CHANNEL_OUT_STEREO,
//                AudioFormat.ENCODING_PCM_16BIT,
//                minBufferSize,
//                AudioTrack.MODE_STREAM
//            )
//            audioTrack.play()
//
//            session.setAudioDecoderStarted(true)
//            LogCollector.log("AAC decoder started")
//        } catch (e: Exception) {
//            LogCollector.log("Error starting audio decoder: ${e.message}")
//        }
//    }
//
//    private fun decodeAac(data: ByteArray, rtpTimestamp: Long) {
//        if (session.getBaseTimestampUs() > 0) {
//            val ptsUs = session.getPresentationTimeUs(rtpTimestamp)
//            val delayUs = ptsUs - SystemClock.elapsedRealtimeNanos() / 1000
//            if (delayUs > 2000) {
//                Thread.sleep(delayUs / 1000)
//            }
//        }
//
//        val index = audioDecoder.dequeueInputBuffer(10000)
//        if (index >= 0) {
//            val inputBuffer = audioDecoder.getInputBuffer(index)
//            inputBuffer?.clear()
//            inputBuffer?.put(data)
//            audioDecoder.queueInputBuffer(index, 0, data.size, SystemClock.elapsedRealtime(), 0)
//        }
//
//        val bufferInfo = MediaCodec.BufferInfo()
//        var outIndex = audioDecoder.dequeueOutputBuffer(bufferInfo, 10000)
//        while (outIndex >= 0) {
//            val outBuffer = audioDecoder.getOutputBuffer(outIndex)
//            val outData = ByteArray(bufferInfo.size)
//            outBuffer?.get(outData)
//            outBuffer?.clear()
//
//            audioTrack.write(outData, 0, outData.size)
//            audioDecoder.releaseOutputBuffer(outIndex, false)
//            outIndex = audioDecoder.dequeueOutputBuffer(bufferInfo, 0)
//        }
//    }
//}