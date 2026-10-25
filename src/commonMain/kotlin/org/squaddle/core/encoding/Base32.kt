package org.squaddle.core.encoding

/**
 * RFC 4648 standard base32, unpadded - PROTOCOL.md §3.1's `RoomRef` display convention
 * (`base32(roomId) "@" relayHost`), §3.5's invite link (`<b32 roomId>/<b32 inviteId>`), and the
 * `/ws` subscribe message's room reference (relay's own
 * `base32.StdEncoding.WithPadding(base32.NoPadding)` in `internal/api/ws.go`/`push.go`).
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

    /** Case-insensitive (relay's own decoder uppercases first, same posture here). `null` on a
     * character outside the alphabet - never throws. */
    public fun decode(text: String): ByteArray? {
        if (text.isEmpty()) return ByteArray(0)
        val upper = text.uppercase()
        val out = ArrayList<Byte>((upper.length * 5) / 8 + 1)
        var buffer = 0
        var bitsInBuffer = 0
        for (c in upper) {
            val value = ALPHABET.indexOf(c)
            if (value < 0) return null
            buffer = (buffer shl 5) or value
            bitsInBuffer += 5
            if (bitsInBuffer >= 8) {
                bitsInBuffer -= 8
                out.add(((buffer ushr bitsInBuffer) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }
}
