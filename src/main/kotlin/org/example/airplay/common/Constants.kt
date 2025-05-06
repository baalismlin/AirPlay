package org.example.airplay.common

val VIDEO_RTP_PORT = 5000
val VIDEO_RTCP_PORT = 5001

val AUDIO_RTP_PORT = 6000
val AUDIO_RTCP_PORT = 6001
val AUDIO_SAMPLE_RATE = 44100
val RTSP_PORT = 60001

// RTSP Request Methods
val METHOD_GET = "GET"
val METHOD_POST = "POST"
val METHOD_OPTIONS = "OPTIONS"
val METHOD_ANNOUNCE = "ANNOUNCE"
val METHOD_SETUP = "SETUP"
val METHOD_RECORD = "RECORD"
val METHOD_PAUSE = "PAUSE"
val METHOD_FLUSH = "FLUSH"
val METHOD_TEARDOWN = "TEARDOWN"
val METHOD_GET_PARAMETER = "GET_PARAMETER"
val METHOD_SET_PARAMETER = "SET_PARAMETER"

// RTSP Request Headers
val HEADER_CSEQ = "cseq"
val HEADER_PUBLIC = "public"
val HEADER_SERVER = "server"
val HEADER_APPLE_CHALLENG =  "apple-challenge"
val HEADER_APPLE_RESPONSE = "apple-response"
val HEADER_CONTENT_TYPE = "content-type"
val HEADER_CONTENT_LENGTH = "content-length"
val HEADER_TRANSPORT = "transport"
val HEADER_SESSION = "session"
val HEADER_ACTIVE_REMOTE = "active-remote"


val MDNS_SERVICE_TYPE = "_airplay._tcp.local."