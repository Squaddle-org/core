package org.squaddle.core.encoding

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** RFC 8949 §4.2.1 round-trip + reject tests for [CanonicalCborCodec]. */
class CanonicalCborTest {

    private fun hex(bytes: ByteArray): String = bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xFF) }

    @Test
    fun uintShortestFormAtEachBoundary() {
        val cases = mapOf(
            0L to "00",
            23L to "17",
            24L to "18 18",
            0xFFL to "18 ff",
            0x100L to "19 01 00",
            0xFFFFL to "19 ff ff",
            0x10000L to "1a 00 01 00 00",
            0xFFFFFFFFL to "1a ff ff ff ff",
            0x100000000L to "1b 00 00 00 01 00 00 00 00",
        )
        for ((value, expectedHex) in cases) {
            val encoded = CanonicalCborCodec.encode(CborValue.UInt(value))
            assertEquals(expectedHex, hex(encoded), "encoding of $value")
            assertEquals(CborValue.UInt(value), CanonicalCborCodec.decode(encoded))
        }
    }

    @Test
    fun negativeIntRoundTrip() {
        val encoded = CanonicalCborCodec.encode(CborValue.NInt(-1))
        assertEquals("20", hex(encoded))
        assertEquals(CborValue.NInt(-1), CanonicalCborCodec.decode(encoded))

        val encoded500 = CanonicalCborCodec.encode(CborValue.NInt(-500))
        assertEquals(CborValue.NInt(-500), CanonicalCborCodec.decode(encoded500))
    }

    @Test
    fun boolAndNullRoundTrip() {
        assertEquals(CborValue.Bool(true), CanonicalCborCodec.decode(CanonicalCborCodec.encode(CborValue.Bool(true))))
        assertEquals(CborValue.Bool(false), CanonicalCborCodec.decode(CanonicalCborCodec.encode(CborValue.Bool(false))))
        assertEquals(CborValue.Null, CanonicalCborCodec.decode(CanonicalCborCodec.encode(CborValue.Null)))
    }

    @Test
    fun textAndBytesRoundTrip() {
        val text = CborValue.Text("Pixel 8")
        assertEquals(text, CanonicalCborCodec.decode(CanonicalCborCodec.encode(text)))

        val bytes = CborValue.Bytes(byteArrayOf(1, 2, 3, 0, -1))
        val decoded = CanonicalCborCodec.decode(CanonicalCborCodec.encode(bytes)) as CborValue.Bytes
        assertContentEquals(bytes.value, decoded.value)
    }

    @Test
    fun arrayRoundTrip() {
        val array = CborValue.Array(listOf(CborValue.UInt(1), CborValue.Text("a"), CborValue.Bool(true)))
        assertEquals(array, CanonicalCborCodec.decode(CanonicalCborCodec.encode(array)))
    }

    @Test
    fun mapKeysAreSortedRegardlessOfInsertionOrder() {
        val outOfOrder = CborValue.Map(
            linkedMapOf(5L to CborValue.UInt(1), 0L to CborValue.UInt(2), 2L to CborValue.UInt(3)),
        )
        val sortedSameEntries = CborValue.Map(
            linkedMapOf(0L to CborValue.UInt(2), 2L to CborValue.UInt(3), 5L to CborValue.UInt(1)),
        )
        val encodedOutOfOrder = CanonicalCborCodec.encode(outOfOrder)
        val encodedSorted = CanonicalCborCodec.encode(sortedSameEntries)
        assertContentEquals(encodedSorted, encodedOutOfOrder)
        // a5 = map(5 keys)? no: map(3) = 0xa3, then key 0x00, value 0x02, key 0x02, value 0x03, key 0x05, value 0x01
        assertEquals("a3 00 02 02 03 05 01", hex(encodedOutOfOrder))
        assertEquals(sortedSameEntries, CanonicalCborCodec.decode(encodedOutOfOrder))
    }

    @Test
    fun deviceCertShapedStructureRoundTrips() {
        // Mirrors PROTOCOL.md §2.2 field layout, without the sig field (as signed over).
        val cert = CborValue.Map(
            linkedMapOf(
                0L to CborValue.UInt(1),
                1L to CborValue.Bytes(ByteArray(32) { it.toByte() }),
                2L to CborValue.Bytes(ByteArray(32) { (it + 1).toByte() }),
                3L to CborValue.Bytes(ByteArray(32) { (it + 2).toByte() }),
                4L to CborValue.Text("Pixel 8"),
                5L to CborValue.UInt(1_700_000_000L),
            ),
        )
        val encoded = CanonicalCborCodec.encode(cert)
        val decoded = CanonicalCborCodec.decode(encoded) as CborValue.Map
        assertEquals(cert.entries.keys, decoded.entries.keys)
        assertEquals(cert.entries[0L], decoded.entries[0L])
        assertContentEquals((cert.entries[1L] as CborValue.Bytes).value, (decoded.entries[1L] as CborValue.Bytes).value)
        assertEquals(cert.entries[4L], decoded.entries[4L])
        assertEquals(cert.entries[5L], decoded.entries[5L])
        // Re-encoding must be byte-identical (determinism is the whole point).
        assertContentEquals(encoded, CanonicalCborCodec.encode(decoded))
    }

    @Test
    fun decodeRejectsIndefiniteLengthMap() {
        // bf = map, indefinite length ; ff = break - exactly what kotlinx-serialization-cbor emits by default.
        val indefinite = byteArrayOf(0xbf.toByte(), 0xff.toByte())
        assertFailsWith<CborFormatException> { CanonicalCborCodec.decode(indefinite) }
    }

    @Test
    fun decodeRejectsNonShortestFormLength() {
        // 18 00 = 1-byte-length-follows encoding of 0, but 0 fits directly in the head byte (non-canonical).
        val overlong = byteArrayOf(0x18, 0x00)
        assertFailsWith<CborFormatException> { CanonicalCborCodec.decode(overlong) }
    }

    @Test
    fun decodeRejectsOutOfOrderMapKeys() {
        // a2 02 00 00 00 = map{2:0, 0:0} - valid CBOR, but keys not ascending => not canonical.
        val outOfOrder = byteArrayOf(0xa2.toByte(), 0x02, 0x00, 0x00, 0x00)
        assertFailsWith<CborFormatException> { CanonicalCborCodec.decode(outOfOrder) }
    }

    @Test
    fun decodeRejectsDuplicateMapKeys() {
        // a2 00 00 00 01 = map{0:0, 0:1} - duplicate key.
        val duplicate = byteArrayOf(0xa2.toByte(), 0x00, 0x00, 0x00, 0x01)
        assertFailsWith<CborFormatException> { CanonicalCborCodec.decode(duplicate) }
    }

    @Test
    fun decodeRejectsTrailingBytes() {
        val encoded = CanonicalCborCodec.encode(CborValue.UInt(1))
        assertFailsWith<CborFormatException> { CanonicalCborCodec.decode(encoded + byteArrayOf(0x00)) }
    }

    @Test
    fun decodeRejectsTruncatedInput() {
        assertTrue(runCatching { CanonicalCborCodec.decode(byteArrayOf(0x19, 0x01)) }.isFailure)
    }
}
