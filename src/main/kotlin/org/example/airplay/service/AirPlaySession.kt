package org.example.airplay.service

import net.i2p.crypto.eddsa.KeyPairGenerator
import java.nio.charset.StandardCharsets
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AirPlaySession(var sessionId: String) {
    val rtspStarted = AtomicBoolean(false)

    val keyPair =  KeyPairGenerator().generateKeyPair()
    var peerPubBytes: ByteArray? = null
    var peerSigBytes: ByteArray? = null
    var selfPubBytes: ByteArray? = null
    var selfPrivateBytes: ByteArray? = null
    var sharedSecret: ByteArray? = null

    var pairVerified: Boolean = false

    val videoDecoderStarted = AtomicBoolean(false)
    val audioDecoderStarted = AtomicBoolean(false)

    var baseTimestampUs: AtomicLong = AtomicLong(-1L)
    var baseMonoTimeUs: AtomicLong = AtomicLong(-1L)

    var decodedKey: ByteArray? = null
    var uri: String? = null
    var mediaTracks: MutableList<MediaTrack> = mutableListOf()

    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class
    )



    fun isRTSPStarted(): Boolean {
        return rtspStarted.get()
    }

    fun setRTSPStarted(value: Boolean) {
        rtspStarted.set(value)
    }

    fun isVideoDecoderStarted(): Boolean {
        return videoDecoderStarted.get()
    }

    fun setVideoDecoderStarted(value: Boolean) {
        videoDecoderStarted.set(value)
    }

    fun isAudioDecoderStarted(): Boolean {
        return audioDecoderStarted.get()
    }

    fun setAudioDecoderStarted(value: Boolean) {
        audioDecoderStarted.set(value)
    }

    fun setBaseTimestampUs(value: Long) {
        baseTimestampUs.set(value)
    }

    fun setBaseMonoTimeUs(value: Long) {
        baseMonoTimeUs.set(value)
    }

    fun getBaseTimestampUs(): Long {
        return baseTimestampUs.get()
    }

    fun getBaseMonoTimeUs(): Long {
        return baseMonoTimeUs.get()
    }

    fun getPresentationTimeUs(timestamp: Long): Long {
        return baseMonoTimeUs.getAndAdd((timestamp * 1000L - baseTimestampUs.get()))
    }
}

data class MediaTrack(
    val type: String, // "audio" / "video"
    val payloadType: Int,
    val encoding: String,
    val clockRate: Int,
    val control: String,
    val fmtp: String? = null
)