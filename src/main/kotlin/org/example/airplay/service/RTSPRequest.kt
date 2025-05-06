package org.example.airplay.service

import org.example.airplay.common.Constants

data class RTSPRequest(
    val method: String,
    val uri: String,
    val version: String,
    val headers: Map<String, String>,
    val payloadBytes: ByteArray?,
) {

    fun getChallenge(): String? {
        return headers[Constants.HEADER_APPLE_CHALLENG]
    }

    fun getCSeq(): String {
        return headers[Constants.HEADER_CSEQ]!!
    }

    fun getContentType(): String? {
        return headers[Constants.HEADER_CONTENT_TYPE]
    }

    fun getTransport(): String? {
        return headers[Constants.HEADER_TRANSPORT]
    }

    fun getSessionId(): String? {
        return headers[Constants.HEADER_ACTIVE_REMOTE]
    }
}

