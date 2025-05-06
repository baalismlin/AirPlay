package org.example.airplay.util

import com.dd.plist.*
import org.example.airplay.common.Constants
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream

object PropertyHelper {

    fun txtAirPlayProps(): Map<String, String> {
        return mapOf(
            "deviceid" to Constants.DEVICE_ID,
            "features" to Constants.FEATURES,
            "flags" to Constants.FLAGS,
            "model" to Constants.MODEL,
            "pi" to Constants.PI,
            "srcvers" to Constants.SRCVERS,
            "vv" to Constants.VV
        )
    }

    fun txtAirPlayBytes(): ByteArray {
        val props = txtAirPlayProps()
        val output = ByteArrayOutputStream()
        for ((key, value) in props) {
            val data = "$key=$value".toByteArray()
            output.write(data.size)
            output.write(data)
        }
        return output.toByteArray()
    }

    fun infoBytes(): ByteArray {

        val dd = NSDictionary()
        val audioFormatDD = NSDictionary()
        audioFormatDD.put("bufferStream", NSArray(NSNumber(21), NSNumber(22), NSNumber(23)))
        dd.put("supportedAudioFormatsExtended", audioFormatDD)
        val playback = NSDictionary()
        playback.put("supportsOfflineHLS", false)
        playback.put("supportsUIForAudioOnlyContent", true)
        playback.put("supportsFPSSecureStop", true)
        playback.put("supportsStopAtEndOfQueue", false)
        playback.put("supportsAirPlayVideoWithSharePlay", true)
        dd.put("statusFlags", 68)
        dd.put("keepAliveSendStatsAsBody", true)
        dd.put("name", Constants.NAME)
        dd.put("deviceid", Constants.DEVICE_ID)
        dd.put("pi", Constants.PI)
        dd.put("txtAirPlay", NSData(txtAirPlayBytes()))
        val formats = NSDictionary()
        formats.put("lowLatencyAudioStream", 0)
        formats.put("screenStream", 21235712)
        formats.put("audioStream", 21235712)
        formats.put("bufferStream", 14680064)
        dd.put("supportedFormats", formats)
        dd.put("sourceVersion", Constants.SRCVERS)
        dd.put("model", Constants.MODEL)
        dd.put("macAddress", Constants.DEVICE_ID)
        dd.put("features", 0x1E shl 32 or 0x5A7FFFF7)
        dd.put("vv", Constants.VV)
        LOGGER.info("payload: ${dd.toXMLPropertyList()}")

        return BinaryPropertyListWriter.writeToArray(dd)
    }

}

private val LOGGER = LoggerFactory.getLogger(PropertyHelper::class.java)