package org.example.airplay.service

import com.dd.plist.NSDictionary

data class RTSPRequest(var method: String = "",
                       var uri: String = "",
                       var version: String = "RTSP/1.0",
                       var headers: Map<String, String> = mapOf(),
                       var payloadBytes: ByteArray? = null,) {

    fun getChallenge(): String? {
        return headers.get(HEADER_APPLE_CHALLENG)
    }

    fun getCSeq(): String {
        return headers.get(HEADER_CSEQ)!!
    }

    fun getContentType(): String? {
        return headers.get(HEADER_CONTENT_TYPE)
    }

    fun getContentLength(): Int {
        return headers.get(HEADER_CONTENT_LENGTH)?.toInt() ?: 0
    }

    fun getTransport(): String? {
        return headers.get(HEADER_TRANSPORT)
    }

    fun getSessionId(): String? {
        return headers.get(HEADER_ACTIVE_REMOTE)
    }


}

