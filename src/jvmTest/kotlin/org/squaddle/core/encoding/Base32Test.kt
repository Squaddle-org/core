package org.squaddle.core.encoding

import kotlin.test.Test
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
}
