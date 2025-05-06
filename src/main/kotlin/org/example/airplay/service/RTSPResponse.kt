package org.example.airplay.service

data class RTSPResponse(val headers: Map<String, String> = mapOf(), val payload: ByteArray? = null) {
    private lateinit var responseCode: String
    private val version = "RTSP/1.0"

    fun ok(): RTSPResponse {
        this.responseCode = "200 OK"
        return this
    }

    fun notImplemented(): RTSPResponse {
        this.responseCode = "501 Not Implemented"
        return this
    }

    fun unauthorized(): RTSPResponse {
        this.responseCode = "401 Unauthorized"
        return this
    }

    fun forbidden(): RTSPResponse {
        this.responseCode = "403 Forbidden"
        return this
    }

    fun build(): ByteArray {
        return buildResponse().toByteArray() + (payload ?: byteArrayOf())
    }

    private fun buildResponse(): String {
        // \r\n is HTTP specification
        return buildString {
            append("$version $responseCode\r\n")
            headers.forEach {
                append("${it.key}: ${it.value}\r\n")
            }
            append("\r\n")
        }
    }

}
