# AirPlay

An AirPlayServer is used to handle the connections with clients (iPhone, iPad, MacBook) supported airplay (video cast,
screen mirror, audio share).

Technically you can connect more than one client to an AirPlayServer at the same time, to simplify the implementation we
will focurs on supporting one client session at the same time period.

An AirPlayServer consists of a mDNS (Multicast DNS) Server, RTSP (Real-Time Streaming Protocol) Server, RTCP (RTP
Control Protocol) Server, Video/Audio Decoder

## mDNS Registraion

- Type: MDNS_SERVICE_TYPE
- Port: RTSP_PORT

## RTSP Server

RTSP Server maintences a socket connection between client and server. The socket uses the same port as mDNS uses.
RTSP Server extracts request data from socket input stream, handles the flowing reqeusts:

1. GET /info
2. POST /pair-setup
3. POST /pair-verify

prepares a response to socket output stream.

### GET /info

### POST /pair-setup

### POST /pair-verify

## RTCP Server

## Audio Decoder

## Video Decoder

