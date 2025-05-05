package org.example.airplay.service

import com.dd.plist.*
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.slf4j.LoggerFactory
import org.whispersystems.curve25519.Curve25519
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPublicKeySpec
import java.util.*
import java.util.Base64
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class RTSPServer(private val sessionManager: SessionManager, private val executor: Executor) {

    private lateinit var serverSocket: ServerSocket
    fun start() {
        executor.execute {
            try {
                serverSocket = ServerSocket(RTSP_PORT)
                LOGGER.info("RTSP server listening on port $RTSP_PORT")

                while (true) {
                    val clientSocket: Socket = serverSocket.accept()
                    executor.execute { handleClient(clientSocket) }
                }
            } catch (e: Exception) {
                LOGGER.info("RTSP server error: ${e.message}")
            }
        }
    }

    fun stop() {
        try {
            serverSocket.close()
            LOGGER.info("RTSP server stopped.")
        } catch (e: Exception) {
            LOGGER.info("Error stopping RTSP server: ${e.message}")
        }
    }

    private fun handleClient(socket: Socket) {
        socket.use {
            val input = BufferedInputStream(socket.getInputStream())
            val output = BufferedOutputStream(socket.getOutputStream())

            while (true) {

                val lines = readRequestLines(input)
                if (lines.isEmpty()) return

                val request = rtspRequest(lines, input)

                val sessionId = request.getSessionId()
                var session: AirPlaySession? = null
                if (sessionId != null) {
                    session = sessionManager.getOrGenerate(sessionId)
                }

                val response = if (request.method == METHOD_GET && request.uri == "/info") {
                    handleInfo(request)
                } else if (request.method == METHOD_POST && request.uri == "/pair-setup" && session != null) {
                    handlePairSetup(request, session)
                } else if (request.method == METHOD_POST && request.uri == "/pair-verify" && session != null) {
                    handlePairVerify(request, session)
                } else {
                    handleElse(request)
                }

                output.write(response.build())
                output.flush()
            }

        }
    }

    private fun handlePairVerify(request: RTSPRequest, session: AirPlaySession): RTSPResponse {
        if (request.payloadBytes?.size != 68) {
            return handleElse(request)
        }

        val flag = request.payloadBytes!![0]

        if (flag > 0) {

            // 用于交换的客户端公钥
            val peerPubBytes = request.payloadBytes!!.sliceArray(IntRange(4, 35))
            session.peerPubBytes = peerPubBytes
            // 用于签名的客户端公钥
            val peerSigBytes = request.payloadBytes!!.sliceArray(IntRange(36, 67))
            session.peerSigBytes = peerSigBytes

//            KeyPairGenerator.getInstance("X25519", "BC")

            // 用于交换的服务端秘钥
            val curve25519 = Curve25519.getInstance(Curve25519.BEST)
            val curve25519KeyPair = curve25519.generateKeyPair()
            // 用于交换的服务端公钥
            val selfPubBytes = curve25519KeyPair.publicKey
            session.selfPubBytes = selfPubBytes
            session.selfPrivateBytes = curve25519KeyPair.privateKey

            val sharedSecret = curve25519.calculateAgreement(peerPubBytes, curve25519KeyPair.privateKey)
            session.sharedSecret = sharedSecret

            val dataToSign = selfPubBytes + peerPubBytes
            val edDSAEngine = EdDSAEngine()
            edDSAEngine.initSign(session.keyPair.private)
            val signature = edDSAEngine.signOneShot(dataToSign)

            val encryptor = initCipher(sharedSecret)
            val encryptedSignature = encryptor.doFinal(signature)

            val payload = selfPubBytes + encryptedSignature

            val headers = mapOf(
                HEADER_CSEQ to request.getCSeq(),
                HEADER_CONTENT_LENGTH to payload.size.toString(),
                HEADER_CONTENT_TYPE to "application/octet-stream",
                HEADER_SERVER to "AirTunes/220.68"
            )

            return RTSPResponse(headers, payload).ok()

        } else {
            val signature = request.payloadBytes!!.sliceArray(IntRange(4, 67))
            val encryptor = initCipher(session.sharedSecret!!)
            var sigBuffer = ByteArray(64)
            encryptor.update(sigBuffer)
            sigBuffer = encryptor.doFinal(signature)

            val sigMessage = session.peerPubBytes!! + session.selfPubBytes!!

            val edDSAEngine = EdDSAEngine()
            val edDSAPublicKey = EdDSAPublicKey(
                EdDSAPublicKeySpec(
                    session.peerSigBytes,
                    EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
                )
            )
            edDSAEngine.initVerify(edDSAPublicKey)

            val pairVerified = edDSAEngine.verifyOneShot(sigMessage, sigBuffer)
            session.pairVerified = pairVerified

            // TODO clean unnecessary keypairs


            val headers = mapOf(
                HEADER_CSEQ to request.getCSeq(),
                HEADER_SERVER to "AirTunes/220.68"
            )

            return RTSPResponse(headers).ok()
        }

    }

    fun initCipher(sharedSecret: ByteArray): Cipher {
        val sha512Digest = MessageDigest.getInstance("SHA-512")
        sha512Digest.update("Pair-Verify-AES-Key".toByteArray(StandardCharsets.UTF_8))
        sha512Digest.update(sharedSecret)
        val sharedSecretSha512AesKey = Arrays.copyOfRange(sha512Digest.digest(), 0, 16)

        sha512Digest.update("Pair-Verify-AES-IV".toByteArray(StandardCharsets.UTF_8))
        sha512Digest.update(sharedSecret)
        val sharedSecretSha512AesIV = Arrays.copyOfRange(sha512Digest.digest(), 0, 16)

        val aesCtr128Encrypt = Cipher.getInstance("AES/CTR/NoPadding")
        aesCtr128Encrypt.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(sharedSecretSha512AesKey, "AES"),
            IvParameterSpec(sharedSecretSha512AesIV)
        )
        return aesCtr128Encrypt
    }

    fun handlePairSetup(request: RTSPRequest, session: AirPlaySession): RTSPResponse {
        if (request.payloadBytes?.size != 32) {
            return handleElse(request)
        }
            val payload = (session.keyPair.public as EdDSAPublicKey).abyte
            val headers = mapOf(
                HEADER_CSEQ to request.getCSeq(),
                HEADER_CONTENT_LENGTH to payload.size.toString(),
                HEADER_CONTENT_TYPE to "application/octet-stream",
                HEADER_SERVER to "AirTunes/220.68"
            )
            return RTSPResponse(headers, payload).ok()
    }

    fun rtspRequest(
        lines: List<String>,
        input: BufferedInputStream
    ): RTSPRequest {
        val requestLine = lines[0]
        val (method, uri, version) = requestLine.split(" ", limit = 3)
        val headers = parseHeaders(lines.drop(1))
        val request = RTSPRequest(method, uri, version, headers)
        val contentLength = request.getContentLength()
        if (contentLength > 0) {
            val payloadBytes = ByteArray(contentLength)
            input.readNBytes(payloadBytes, 0, contentLength)
            request.payloadBytes = payloadBytes
        }
        LOGGER.info("Request: ${request}")
        return request
    }

    fun parseHeaders(lines: List<String>): Map<String, String> {
        return lines.mapNotNull {
            val parts = it.split(":", limit = 2)
            if (parts.size == 2) parts[0].trim().lowercase() to parts[1].trim() else null
        }.toMap()
    }

    fun handleInfo(request: RTSPRequest): RTSPResponse {
        if (request.uri == "/info") {
            val props = mapOf(
                "deviceid" to "02:11:32:AC:45:00",
                "features" to "0x5A7FFEE6",
                "flags" to "0x4",
                "model" to "AppleTV2,1",
                "pi" to "2e388006-13ba-4041-9a67-25dd4a43d536",
                "srcvers" to "220.68",
                "vv" to "2"
            )

            val output = ByteArrayOutputStream()
            for ((key, value) in props) {
                val data = "$key=$value".toByteArray()
                output.write(data.size)
                output.write(data)
            }

            val dd = NSDictionary()
            val audioFormatDD = NSDictionary()
            audioFormatDD.put("bufferStream", NSArray(NSNumber(21), NSNumber(22), NSNumber(23)))
            dd.put("supportedAudioFormatsExtended", audioFormatDD)
            val playback = NSDictionary()
            playback.put("supportsOfflineHLS", NSNumber(false))
            playback.put("supportsUIForAudioOnlyContent", NSNumber(true))
            playback.put("supportsFPSSecureStop", NSNumber(true))
            playback.put("supportsStopAtEndOfQueue", NSNumber(false))
            playback.put("supportsAirPlayVideoWithSharePlay", NSNumber(true))
            dd.put("statusFlags", NSNumber(68))
            dd.put("keepAliveSendStatsAsBody", NSNumber(true))
            dd.put("name", NSString("Lin Feng's TV"))
            dd.put("deviceid", NSString(props.get("deviceid")))
            dd.put("pi", NSString(props.get("pi")))
            dd.put("txtAirPlay", NSData(output.toByteArray()))
            val formats = NSDictionary()
            formats.put("lowLatencyAudioStream", NSNumber(0))
            formats.put("screenStream", NSNumber(21235712))
            formats.put("audioStream", NSNumber(21235712))
            formats.put("bufferStream", NSNumber(14680064))
            dd.put("supportedFormats", formats)
            dd.put("sourceVersion", NSString(props.get("srcvers")))
            dd.put("model", NSString(props.get("model")))
            dd.put("macAddress", NSString("02:11:32:AC:45:00"))
            dd.put("features", NSNumber(0x1E shl 32 or 0x5A7FFFF7))
            dd.put("vv", NSString(props.get("vv")))
            LOGGER.info("payload: ${dd.toXMLPropertyList()}")

            val payload = BinaryPropertyListWriter.writeToArray(dd)

            val headers = mapOf(
                HEADER_CSEQ to request.getCSeq(),
                HEADER_CONTENT_LENGTH to payload.size.toString(),
                HEADER_CONTENT_TYPE to "application/x-apple-binary-plist",
                HEADER_SERVER to "AirTunes/220.68"
            )

            return RTSPResponse(headers, payload).ok()
        } else {
            return handleElse(request)
        }
    }

    fun readRequestLines(input: InputStream): List<String> {
        val lines = mutableListOf<String>()
        val buffer = ByteArrayOutputStream()
        var prev = 0
        var curr: Int

        while (true) {
            curr = input.read()
            if (curr == -1) break

            if (prev == '\r'.code && curr == '\n'.code) {
                val line = buffer.toString().trimEnd()
                if (line.isEmpty()) break
                lines.add(line)
                buffer.reset()
            } else if (curr != '\r'.code) {
                buffer.write(curr)
            }
            prev = curr
        }

        return lines
    }

    private fun handleTeardown(request: RTSPRequest): RTSPResponse {

        val headers = mapOf(
            HEADER_CSEQ to request.getCSeq(),
//            HEADER_SESSION to session.sessionId
        )
        return RTSPResponse(headers).ok()
    }

    private fun handleRecord(request: RTSPRequest): RTSPResponse {

        val headers = mapOf(
            HEADER_CSEQ to request.getCSeq(),
//            HEADER_SESSION to session.sessionId
        )
        return RTSPResponse(headers).ok()
    }

    private fun handleSetup(request: RTSPRequest): RTSPResponse {

        val headers = mutableMapOf(
            HEADER_CSEQ to request.getCSeq(),
//            HEADER_SESSION to session.sessionId
        )
        val transport = request.getTransport() ?: ""
        if (transport.contains("client_port=5000-5001")) {
            headers.put(
                HEADER_TRANSPORT,
                "RTP/AVP/UDP;unicast;client_port=5000-5001;server_port=5000-5001"
            )
        } else if (transport.contains("client_port=6000-6001")) {
            headers.put(
                HEADER_TRANSPORT,
                "RTP/AVP/UDP;unicast;client_port=6000-6001;server_port=6000-6001"
            )
        }

        return RTSPResponse(headers).ok()
    }

    private fun handleAnnounce(request: RTSPRequest): RTSPResponse {
        // 如果是 ANNOUNCE，读取 SDP 内容
        if (request.getContentType() == "application/sdp" && request.payloadBytes != null) {
            parseSdp("request.payloadBytes!!")
        }

        val headers = mapOf(
            HEADER_CSEQ to request.getCSeq(),
        )
        return RTSPResponse(headers).ok()
    }

    private fun handleElse(request: RTSPRequest): RTSPResponse {
        val headers = mapOf(
            HEADER_CSEQ to request.getCSeq()
        )
        return RTSPResponse(headers).notImplemented()
    }

    private fun handleOptions(request: RTSPRequest): RTSPResponse {
        var challenge: String?
        if (request.getChallenge().also { challenge = it } != null) {

//            val decoded = Base64.getDecoder().decode(challenge!!)
//            val padded = ByteArray(32)
//            System.arraycopy(decoded, 0, padded, 0, decoded.size.coerceAtMost(32))
//
//            // Add IP (usually 4 bytes), MAC (6 bytes), pad if needed
//            val addressBytes = InetAddress.getLocalHost().address
//            System.arraycopy(addressBytes, 0, padded, decoded.size, addressBytes.size.coerceAtMost(4))

//            val encrypted = RsaHelper.encryptWithPrivateKey(padded)
//            val encoded = Base64.getEncoder().encodeToString(encrypted)
//            response.headers.put(HEADER_APPLE_RESPONSE, encoded)
        }
        var headers = mapOf(
            HEADER_CSEQ to request.getCSeq(),
            HEADER_PUBLIC to "OPTIONS, ANNOUNCE, SETUP, RECORD, PAUSE, TEARDOWN, GET, POST, FLUSH, GET_PARAMETER, SET_PARAMETER",
            HEADER_SERVER to "AirTunes/366.0",
            HEADER_CONTENT_LENGTH to "0"
        )

        return RTSPResponse(headers).ok()
    }

    private fun parseSdp(sdp: String) {

        val lines = sdp.lines().map { it.trim() }

        var currentType: String? = null
        var payloadType = -1
        var encoding = ""
        var clockRate = 0
        var control = ""
        var fmtp: String? = null

        for (line in lines) {
            when {
                line.startsWith("m=") -> {
                    // m=video 5000 RTP/AVP 96
                    // m=audio 5002 RTP/AVP 97
                    if (currentType != null && payloadType != -1) {
                            MediaTrack(currentType, payloadType, encoding, clockRate, control, fmtp)
                    }

                    val parts = line.split(" ")
                    currentType = parts[0].substringAfter("m=")
                    payloadType = parts.getOrNull(3)?.toIntOrNull() ?: -1
                    encoding = ""
                    clockRate = 0
                    control = ""
                    fmtp = null
                }

                line.startsWith("a=rtpmap:") -> {
                    val match = Regex("a=rtpmap:(\\d+) ([^/]+)/([0-9]+)").find(line)
                    if (match != null) {
                        payloadType = match.groupValues[1].toInt()
                        encoding = match.groupValues[2]
                        clockRate = match.groupValues[3].toInt()
                    }
                }

                line.startsWith("a=control:") -> {
                    control = line.substringAfter("a=control:")
                }

                line.startsWith("a=fmtp:") -> {
                    fmtp = line.substringAfter("a=fmtp:")
                }

                line.startsWith("a=crypto:") -> {
                    // 示例: a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNvYkEyYmNkZWYzZ2hpamtsbW5vcA==
                    val parts = line.split("inline:")
                    if (parts.size > 1) {
                        val key = parts[1].split(" ")[0]
                        Base64.getDecoder().decode(key)
                        LOGGER.info("Parsed SDES key (base64): $key")
                    }
                }
            }
        }

        // flush final track
        if (currentType != null && payloadType != -1) {
                MediaTrack(currentType, payloadType, encoding, clockRate, control, fmtp)
        }
    }

    private fun generateDigestResponse(
        username: String,
        nonce: String,
        realm: String,
        method: String,
        uri: String,
        password: String = "AirPlay" // 默认密码
    ): String {
        val md5 = MessageDigest.getInstance("MD5")

        fun md5Hex(data: String): String {
            return md5.digest(data.toByteArray()).joinToString("") { "%02x".format(it) }
        }

        val ha1 = md5Hex("$username:$realm:$password")
        val ha2 = md5Hex("$method:$uri")
        return md5Hex("$ha1:$nonce:$ha2")
    }
}

private val LOGGER = LoggerFactory.getLogger(RTSPServer::class.java)