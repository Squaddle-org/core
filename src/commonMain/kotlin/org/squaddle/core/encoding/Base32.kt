package org.squaddle.core.encoding

/**
 * RFC 4648 standard base32, unpadded, uppercase - PROTOCOL.md §3.1's `RoomRef` display convention
 * (`base32(roomId) "@" relayHost`) and the `/ws` subscribe message's room reference (relay's own
 * `base32.StdEncoding.WithPadding(base32.NoPadding)` in `internal/api/ws.go`/`push.go`). No
 * decoder needed yet - nothing in core currently receives a base32 room ref back from the wire.
 */
public object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    public fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val out = StringBuilder((bytes.size * 8 + 4) / 5)
        var buffer = 0
        var bitsInBuffer = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsInBuffer += 8
            while (bitsInBuffer >= 5) {
                bitsInBuffer -= 5
                out.append(ALPHABET[(buffer ushr bitsInBuffer) and 0x1F])
            }
        }
        if (bitsInBuffer > 0) {
            out.append(ALPHABET[(buffer shl (5 - bitsInBuffer)) and 0x1F])
        }
        return out.toString()
    }
}
