package org.squaddle.core.encoding

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** RFC 4648 §10 test vectors, unpadded. */
class Base32Test {
    @Test
    fun matchesRfc4648TestVectors() {
        assertEquals("", Base32.encode("".encodeToByteArray()))
        assertEquals("MY", Base32.encode("f".encodeToByteArray()))
        assertEquals("MZXQ", Base32.encode("fo".encodeToByteArray()))
        assertEquals("MZXW6", Base32.encode("foo".encodeToByteArray()))
        assertEquals("MZXW6YQ", Base32.encode("foob".encodeToByteArray()))
        assertEquals("MZXW6YTB", Base32.encode("fooba".encodeToByteArray()))
        assertEquals("MZXW6YTBOI", Base32.encode("foobar".encodeToByteArray()))
    }

    @Test
    fun decodeMatchesRfc4648TestVectors() {
        assertContentEquals("f".encodeToByteArray(), Base32.decode("MY")!!)
        assertContentEquals("foo".encodeToByteArray(), Base32.decode("MZXW6")!!)
        assertContentEquals("foobar".encodeToByteArray(), Base32.decode("MZXW6YTBOI")!!)
    }

    @Test
    fun decodeIsCaseInsensitive() {
        assertContentEquals("foobar".encodeToByteArray(), Base32.decode("mzxw6ytboi")!!)
    }

    @Test
    fun decodeRejectsInvalidCharacters() {
        assertEquals(null, Base32.decode("01189"))
    }

    @Test
    fun randomBytesRoundTripThroughEncodeAndDecode() {
        val bytes = ByteArray(32) { (it * 7).toByte() }
        assertContentEquals(bytes, Base32.decode(Base32.encode(bytes))!!)
    }
}
