package org.example.airplay.common

object Constants {

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
    val HEADER_APPLE_CHALLENG = "apple-challenge"
    val HEADER_APPLE_RESPONSE = "apple-response"
    val HEADER_CONTENT_TYPE = "content-type"
    val HEADER_CONTENT_LENGTH = "content-length"
    val HEADER_TRANSPORT = "transport"
    val HEADER_SESSION = "session"
    val HEADER_ACTIVE_REMOTE = "active-remote"
    val APPLICATION_TYPE_PLIST = "application/x-apple-binary-plist"
    val APPLICATION_TYPE_STREAM = "application/octet-stream"

    val MDNS_SERVICE_TYPE = "_airplay._tcp.local."


    // Props values
    val NAME = "AirPlayTV"
    val DEVICE_ID = "02:11:32:AC:45:00"
    val FEATURES = "0x5A7FFEE6"
    val FLAGS = "0x4"
    val MODEL = "AppleTV2,1"
    val PI = "2e388006-13ba-4041-9a67-25dd4a43d536"
    val SRCVERS = "220.68"
    val SERVER = "AirTunes/220.68"
    val VV = "2"
}