package org.squaddle.core.encoding

/**
 * Deterministic CBOR (RFC 8949 §4.2.1): shortest-form ints, definite lengths,
 * map keys sorted by encoded bytes. Everything that is hashed or signed goes through here.
 *
 * kotlinx-serialization-cbor was evaluated and rejected: by default (and with
 * `useDefiniteLengthEncoding = true`) it still emits maps in declaration order rather than sorted
 * by canonical key bytes, so it cannot be used for anything that is hashed or signed. [CanonicalCborCodec]
 * is a minimal hand-written encoder/decoder instead.
 */
public interface CanonicalCbor {
    public fun encode(value: CborValue): ByteArray
    public fun decode(bytes: ByteArray): CborValue
}

public sealed interface CborValue {
    public data class UInt(val value: Long) : CborValue
    public data class NInt(val value: Long) : CborValue
    public class Bytes(public val value: ByteArray) : CborValue
    public data class Text(val value: String) : CborValue
    public data class Array(val items: List<CborValue>) : CborValue
    public data class Map(val entries: kotlin.collections.Map<Long, CborValue>) : CborValue
    public data class Bool(val value: Boolean) : CborValue
    public data object Null : CborValue
}

/** Thrown by [CanonicalCborCodec.decode] on anything that is not the unique canonical encoding. */
public class CborFormatException(message: String) : Exception(message)

/**
 * Minimal canonical CBOR per RFC 8949 §4.2.1, restricted to what PROTOCOL.md structures need:
 * unsigned/negative ints, byte strings, text strings, arrays, maps with non-negative [Long] keys,
 * booleans and null. Map keys in this subset are always encoded shortest-form, so ascending
 * numeric key order is exactly ascending encoded-byte order - sorting by [Long] is sufficient.
 *
 * [decode] rejects anything that is not *the* canonical encoding (indefinite length, non-shortest
 * ints, unsorted or duplicate map keys) - for structures that get hashed or signed, accepting a
 * second valid byte-encoding of the same logical value would let an attacker produce two different
 * hashes/signatures for what the protocol considers one and the same structure.
 */
public object CanonicalCborCodec : CanonicalCbor {

    override fun encode(value: CborValue): ByteArray {
        val out = ByteBuf()
        writeValue(out, value)
        return out.toByteArray()
    }

    override fun decode(bytes: ByteArray): CborValue {
        val reader = ByteReader(bytes)
        val value = readValue(reader)
        if (reader.hasRemaining()) throw CborFormatException("trailing bytes after top-level value")
        return value
    }

    // ---- encoding ----

    private const val MAJOR_UINT = 0
    private const val MAJOR_NINT = 1
    private const val MAJOR_BYTES = 2
    private const val MAJOR_TEXT = 3
    private const val MAJOR_ARRAY = 4
    private const val MAJOR_MAP = 5
    private const val MAJOR_SIMPLE = 7

    private const val SIMPLE_FALSE = 20
    private const val SIMPLE_TRUE = 21
    private const val SIMPLE_NULL = 22

    private fun writeValue(out: ByteBuf, value: CborValue) {
        when (value) {
            is CborValue.UInt -> writeHead(out, MAJOR_UINT, value.value)
            is CborValue.NInt -> {
                require(value.value < 0) { "NInt must be negative, was ${value.value}" }
                writeHead(out, MAJOR_NINT, -value.value - 1)
            }
            is CborValue.Bytes -> {
                writeHead(out, MAJOR_BYTES, value.value.size.toLong())
                out.write(value.value)
            }
            is CborValue.Text -> {
                val utf8 = value.value.encodeToByteArray()
                writeHead(out, MAJOR_TEXT, utf8.size.toLong())
                out.write(utf8)
            }
            is CborValue.Array -> {
                writeHead(out, MAJOR_ARRAY, value.items.size.toLong())
                for (item in value.items) writeValue(out, item)
            }
            is CborValue.Map -> {
                writeHead(out, MAJOR_MAP, value.entries.size.toLong())
                for (key in value.entries.keys.sorted()) {
                    require(key >= 0) { "canonical map keys must be non-negative, was $key" }
                    writeHead(out, MAJOR_UINT, key)
                    writeValue(out, value.entries.getValue(key))
                }
            }
            is CborValue.Bool -> out.write(byte(MAJOR_SIMPLE, if (value.value) SIMPLE_TRUE else SIMPLE_FALSE))
            is CborValue.Null -> out.write(byte(MAJOR_SIMPLE, SIMPLE_NULL))
        }
    }

    /** Shortest-form major-type + argument, per RFC 8949 §3.1/§4.2.1. [argument] MUST be >= 0. */
    private fun writeHead(out: ByteBuf, majorType: Int, argument: Long) {
        require(argument >= 0) { "cbor length/argument must be non-negative, was $argument" }
        when {
            argument < 24 -> out.write(byte(majorType, argument.toInt()))
            argument <= 0xFFL -> {
                out.write(byte(majorType, 24))
                out.write(argument.toInt())
            }
            argument <= 0xFFFFL -> {
                out.write(byte(majorType, 25))
                out.writeBE(argument, 2)
            }
            argument <= 0xFFFFFFFFL -> {
                out.write(byte(majorType, 26))
                out.writeBE(argument, 4)
            }
            else -> {
                out.write(byte(majorType, 27))
                out.writeBE(argument, 8)
            }
        }
    }

    private fun byte(majorType: Int, additional: Int): Int = (majorType shl 5) or additional

    // ---- decoding ----

    private fun readValue(reader: ByteReader): CborValue {
        val first = reader.peek()
        val majorType = (first ushr 5) and 0x07
        return when (majorType) {
            MAJOR_UINT -> CborValue.UInt(readHeadArgument(reader, MAJOR_UINT))
            MAJOR_NINT -> {
                val n = readHeadArgument(reader, MAJOR_NINT)
                CborValue.NInt(-n - 1)
            }
            MAJOR_BYTES -> CborValue.Bytes(reader.take(readHeadArgument(reader, MAJOR_BYTES).toIntExact("byte string length")))
            MAJOR_TEXT -> CborValue.Text(
                reader.take(readHeadArgument(reader, MAJOR_TEXT).toIntExact("text string length")).decodeToString(),
            )
            MAJOR_ARRAY -> {
                val count = readHeadArgument(reader, MAJOR_ARRAY).toIntExact("array length")
                CborValue.Array(List(count) { readValue(reader) })
            }
            MAJOR_MAP -> {
                val count = readHeadArgument(reader, MAJOR_MAP).toIntExact("map length")
                val entries = LinkedHashMap<Long, CborValue>(count)
                var previousKey: Long? = null
                repeat(count) {
                    val keyFirst = reader.peek()
                    if ((keyFirst ushr 5) and 0x07 != MAJOR_UINT) {
                        throw CborFormatException("map key must be an unsigned integer")
                    }
                    val key = readHeadArgument(reader, MAJOR_UINT)
                    if (previousKey != null && key <= previousKey) {
                        throw CborFormatException("map keys not in strictly ascending canonical order")
                    }
                    previousKey = key
                    entries[key] = readValue(reader)
                }
                CborValue.Map(entries)
            }
            MAJOR_SIMPLE -> {
                val b = reader.next()
                when (b) {
                    byte(MAJOR_SIMPLE, SIMPLE_FALSE) -> CborValue.Bool(false)
                    byte(MAJOR_SIMPLE, SIMPLE_TRUE) -> CborValue.Bool(true)
                    byte(MAJOR_SIMPLE, SIMPLE_NULL) -> CborValue.Null
                    else -> throw CborFormatException("unsupported simple value 0x${b.toString(16)}")
                }
            }
            else -> throw CborFormatException("unsupported major type $majorType")
        }
    }

    /** Reads a shortest-form length/argument for [expectedMajorType], rejecting indefinite length and overlong forms. */
    private fun readHeadArgument(reader: ByteReader, expectedMajorType: Int): Long {
        val first = reader.next()
        val majorType = (first ushr 5) and 0x07
        if (majorType != expectedMajorType) {
            throw CborFormatException("expected major type $expectedMajorType, got $majorType")
        }
        val additional = first and 0x1F
        return when {
            additional < 24 -> additional.toLong()
            additional == 24 -> {
                val v = reader.next().toLong()
                if (v < 24) throw CborFormatException("non-shortest-form 1-byte length encoding ($v)")
                v
            }
            additional == 25 -> {
                val v = reader.takeBE(2)
                if (v <= 0xFFL) throw CborFormatException("non-shortest-form 2-byte length encoding ($v)")
                v
            }
            additional == 26 -> {
                val v = reader.takeBE(4)
                if (v <= 0xFFFFL) throw CborFormatException("non-shortest-form 4-byte length encoding ($v)")
                v
            }
            additional == 27 -> {
                val v = reader.takeBE(8)
                if (v <= 0xFFFFFFFFL) throw CborFormatException("non-shortest-form 8-byte length encoding ($v)")
                v
            }
            additional == 31 -> throw CborFormatException("indefinite-length items are not canonical")
            else -> throw CborFormatException("reserved additional info value $additional")
        }
    }

    private fun Long.toIntExact(what: String): Int {
        if (this > Int.MAX_VALUE.toLong()) throw CborFormatException("$what $this exceeds supported size")
        return this.toInt()
    }
}

/** Minimal growable byte buffer - no java.io in commonMain. */
private class ByteBuf {
    private var buf = ByteArray(32)
    private var size = 0

    private fun ensure(extra: Int) {
        if (size + extra > buf.size) {
            var newCapacity = buf.size * 2
            while (newCapacity < size + extra) newCapacity *= 2
            buf = buf.copyOf(newCapacity)
        }
    }

    fun write(byteValue: Int) {
        ensure(1)
        buf[size] = byteValue.toByte()
        size += 1
    }

    fun write(bytes: ByteArray) {
        ensure(bytes.size)
        bytes.copyInto(buf, size)
        size += bytes.size
    }

    fun writeBE(value: Long, numBytes: Int) {
        ensure(numBytes)
        for (i in numBytes - 1 downTo 0) {
            buf[size + (numBytes - 1 - i)] = ((value ushr (i * 8)) and 0xFF).toByte()
        }
        size += numBytes
    }

    fun toByteArray(): ByteArray = buf.copyOf(size)
}

/** Minimal forward-only byte reader. */
private class ByteReader(private val bytes: ByteArray) {
    private var pos = 0

    fun hasRemaining(): Boolean = pos < bytes.size

    fun peek(): Int {
        if (pos >= bytes.size) throw CborFormatException("unexpected end of input")
        return bytes[pos].toInt() and 0xFF
    }

    fun next(): Int {
        val b = peek()
        pos += 1
        return b
    }

    fun take(length: Int): ByteArray {
        if (length < 0 || pos + length > bytes.size) throw CborFormatException("unexpected end of input")
        val out = bytes.copyOfRange(pos, pos + length)
        pos += length
        return out
    }

    fun takeBE(numBytes: Int): Long {
        var result = 0L
        repeat(numBytes) { result = (result shl 8) or next().toLong() }
        return result
    }
}
