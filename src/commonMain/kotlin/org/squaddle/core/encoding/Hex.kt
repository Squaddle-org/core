package org.squaddle.core.encoding

/**
 * Portable byte-array hex encoding. `"%02x".format(it)` (seen independently in five places
 * across this module before this consolidation) is JVM-only (`java.util.Formatter`) and fails to
 * compile on `js(IR)`/`wasmJs` - found while spiking ADR-0009. Every call site needing a stable
 * hex string key (`ByteArray` has reference equality/hashCode, breaking `Map`/`Set` usage) should
 * go through this rather than reintroducing `.format`.
 */
public object Hex {
    private const val DIGITS = "0123456789abcdef"

    public fun encode(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(DIGITS[v ushr 4])
            sb.append(DIGITS[v and 0x0F])
        }
        return sb.toString()
    }

    public fun decode(hex: String): ByteArray = ByteArray(hex.length / 2) { i ->
        (DIGITS.indexOf(hex[i * 2]).shl(4) or DIGITS.indexOf(hex[i * 2 + 1])).toByte()
    }
}
