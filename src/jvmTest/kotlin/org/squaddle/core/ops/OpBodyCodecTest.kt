package org.squaddle.core.ops

import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * [OpBody]'s data classes carry `ByteArray` fields, whose generated `equals()` is reference, not
 * content, equality (a Kotlin gotcha, same reason other byte-array-bearing structures in this
 * codebase compare via `assertContentEquals`/re-encoded bytes rather than `assertEquals` on the
 * object itself) - so round-trip here is asserted via re-encoded canonical CBOR bytes, which is
 * both a correct equality check (canonical encoding is deterministic) and a stronger one (it also
 * re-verifies decode-then-encode symmetry, not just field-by-field equality).
 */
class OpBodyCodecTest {

    private fun roundTripBytes(body: OpBody): ByteArray = decodeOpBody(body.encode())!!.encode()

    @Test
    fun ideaCreateRoundTrips() {
        val body = OpBody.IdeaCreate(ByteArray(16) { it.toByte() }, "Camping trip", "long weekend", listOf("outdoors", "summer"))
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun ideaCreateWithoutOptionalFieldsRoundTrips() {
        val body = OpBody.IdeaCreate(ByteArray(16), "x", null, emptyList())
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun ideaSetWithTextValueRoundTrips() {
        val body = OpBody.IdeaSet(ByteArray(16), "title", "New title")
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun ideaSetWithTagsListValueRoundTrips() {
        val body = OpBody.IdeaSet(ByteArray(16), "tags", listOf("a", "b"))
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun ideaSetWithNullValueRoundTrips() {
        val body = OpBody.IdeaSet(ByteArray(16), "desc", null)
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun voteSetNegativeValueRoundTrips() {
        val body = OpBody.VoteSet(ByteArray(16), -1)
        assertContentEquals(body.encode(), roundTripBytes(body))
        assertEquals(-1, (decodeOpBody(body.encode()) as OpBody.VoteSet).value)
    }

    @Test
    fun voteSetZeroAndPositiveRoundTrip() {
        val zero = OpBody.VoteSet(ByteArray(16), 0)
        val one = OpBody.VoteSet(ByteArray(16), 1)
        assertContentEquals(zero.encode(), roundTripBytes(zero))
        assertContentEquals(one.encode(), roundTripBytes(one))
        assertEquals(0, (decodeOpBody(zero.encode()) as OpBody.VoteSet).value)
        assertEquals(1, (decodeOpBody(one.encode()) as OpBody.VoteSet).value)
    }

    @Test
    fun commentAddRoundTrips() {
        val body = OpBody.CommentAdd(ByteArray(16), ByteArray(16) { 1 }, "nice idea")
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun eventCreateRoundTrips() {
        val body = OpBody.EventCreate(ByteArray(16), ByteArray(16) { 2 }, "Game night", 1_700_000_000L, 1_700_010_000L, "Europe/Berlin", "My place", false)
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun eventCreateWithoutOptionalFieldsRoundTrips() {
        val body = OpBody.EventCreate(ByteArray(16), null, "Game night", 1_700_000_000L, null, "UTC", null, true)
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun rsvpSetRoundTrips() {
        val body = OpBody.RsvpSet(ByteArray(16), "yes")
        assertContentEquals(body.encode(), roundTripBytes(body))
    }

    @Test
    fun profileSetRoundTrips() {
        val body = OpBody.ProfileSet("Alice", "🎉")
        assertEquals(body, decodeOpBody(body.encode())) // no ByteArray fields - plain equals() is fine here
    }

    @Test
    fun unknownTypeDecodesToUnknownNotNull() {
        val encoded = OpBody.Unknown("future.type").encode()
        // Unknown's own encode() writes an empty payload (nothing to round-trip semantically -
        // only ever decoded, never constructed to re-encode in practice), but decoding a type
        // string this implementation doesn't recognize must still succeed per §4.2 ("Unknown
        // types MUST be ignored"), not fail the whole envelope.
        assertEquals(OpBody.Unknown("future.type"), decodeOpBody(encoded))
    }

    @Test
    fun malformedCborDecodesToNull() {
        assertNull(decodeOpBody(byteArrayOf(0xff.toByte())))
    }

    @Test
    fun knownTypeWithMissingRequiredFieldDecodesToNull() {
        // "idea.create" without its required title (key 1) must reject, not throw or silently
        // substitute a default.
        val malformed = CanonicalCborCodec.encode(
            CborValue.Map(
                mapOf(
                    0L to CborValue.Text("idea.create"),
                    1L to CborValue.Map(mapOf(0L to CborValue.Bytes(ByteArray(16)))),
                ),
            ),
        )
        assertNull(decodeOpBody(malformed))
    }
}
