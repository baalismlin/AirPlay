package org.example.airplay

import org.example.airplay.service.AirPlayServer

fun main() {
    val server = AirPlayServer()
    try {
        server.start()
    } catch (e: Exception) {
        server.stop()
    }

}