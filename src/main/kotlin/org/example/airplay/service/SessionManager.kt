package org.example.airplay.service

class SessionManager {
    private val sessions: MutableMap<String, AirPlaySession> = mutableMapOf()

    fun getOrGenerate(sessionId: String): AirPlaySession {
        return sessions.getOrPut(sessionId) { AirPlaySession(sessionId) }
    }

}