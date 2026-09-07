package com.cyberkit.app.apk

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure Kotlin Android Binary XML (AXML) Decoder.
 * Decodes binary AndroidManifest.xml from APKs into standard readable XML.
 */
object AxmlDecoder {

    private const val CHUNK_AXML_FILE = 0x00080003
    private const val CHUNK_STRING_POOL = 0x001C0001
    private const val CHUNK_RESOURCE_MAP = 0x00080180
    private const val CHUNK_START_NAMESPACE = 0x00100100
    private const val CHUNK_END_NAMESPACE = 0x00100101
    private const val CHUNK_START_TAG = 0x00100102
    private const val CHUNK_END_TAG = 0x00100103
    private const val CHUNK_TEXT = 0x00100104

    fun decode(bytes: ByteArray): String {
        return try {
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val header = buffer.int
            if (header != CHUNK_AXML_FILE) {
                // If not binary XML, check if it's already plain text
                val testStr = String(bytes.take(100).toByteArray())
                if (testStr.contains("<manifest") || testStr.contains("<?xml")) {
                    return String(bytes, Charsets.UTF_8)
                }
                return "<!-- Not a valid Android Binary XML header -->"
            }

            buffer.int // File size
            val stringTable = mutableListOf<String>()
            val out = StringBuilder()
            out.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")

            while (buffer.hasRemaining()) {
                val chunkStart = buffer.position()
                val chunkType = buffer.int
                val chunkSize = buffer.int

                if (chunkSize <= 0 || chunkStart + chunkSize > buffer.limit()) break

                when (chunkType) {
                    CHUNK_STRING_POOL -> {
                        val stringCount = buffer.int
                        val styleCount = buffer.int
                        val flags = buffer.int
                        val stringsStart = buffer.int
                        val stylesStart = buffer.int

                        val isUtf8 = (flags and (1 shl 8)) != 0
                        val stringOffsets = IntArray(stringCount)
                        for (i in 0 until stringCount) {
                            stringOffsets[i] = buffer.int
                        }

                        val poolDataOffset = chunkStart + stringsStart
                        for (offset in stringOffsets) {
                            val pos = poolDataOffset + offset
                            if (pos in 0 until buffer.limit()) {
                                buffer.position(pos)
                                val str = if (isUtf8) readUtf8String(buffer) else readUtf16String(buffer)
                                stringTable.add(str)
                            } else {
                                stringTable.add("")
                            }
                        }
                    }

                    CHUNK_START_TAG -> {
                        buffer.int // line number
                        buffer.int // comment
                        val namespaceIdx = buffer.int
                        val nameIdx = buffer.int
                        buffer.int // attr start
                        val attrSize = buffer.int
                        val attrCount = buffer.int
                        buffer.int // id index
                        buffer.int // class index
                        buffer.int // style index

                        val tagName = stringTable.getOrElse(nameIdx) { "unknown" }
                        out.append("  <$tagName")

                        for (i in 0 until attrCount) {
                            val attrNsIdx = buffer.int
                            val attrNameIdx = buffer.int
                            val attrValIdx = buffer.int
                            val attrType = buffer.int
                            val attrData = buffer.int

                            val attrName = stringTable.getOrElse(attrNameIdx) { "attr_$i" }
                            val attrValue = if (attrValIdx in stringTable.indices) {
                                stringTable[attrValIdx]
                            } else {
                                formatAttributeValue(attrType, attrData)
                            }
                            out.append(" $attrName=\"$attrValue\"")
                        }
                        out.append(">\n")
                    }

                    CHUNK_END_TAG -> {
                        buffer.int // line
                        buffer.int // comment
                        val nsIdx = buffer.int
                        val nameIdx = buffer.int
                        val tagName = stringTable.getOrElse(nameIdx) { "unknown" }
                        out.append("  </$tagName>\n")
                    }

                    else -> {
                        // Skip other chunks
                    }
                }

                buffer.position(chunkStart + chunkSize)
            }

            out.toString()
        } catch (e: Exception) {
            "<!-- Error decoding binary manifest: ${e.message} -->"
        }
    }

    private fun readUtf8String(buffer: ByteBuffer): String {
        if (!buffer.hasRemaining()) return ""
        val len = buffer.get().toInt() and 0xFF
        val bytes = ByteArray(len)
        buffer.get(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    private fun readUtf16String(buffer: ByteBuffer): String {
        if (!buffer.hasRemaining()) return ""
        val charCount = buffer.short.toInt() and 0xFFFF
        val chars = CharArray(charCount)
        for (i in 0 until charCount) {
            if (buffer.hasRemaining()) {
                chars[i] = buffer.char
            }
        }
        return String(chars)
    }

    private fun formatAttributeValue(type: Int, data: Int): String {
        return when (type) {
            3 -> data.toString()
            16 -> data.toString()
            17 -> "0x" + Integer.toHexString(data)
            18 -> if (data != 0) "true" else "false"
            else -> data.toString()
        }
    }
}
