package org.squaddle.core

import org.squaddle.core.ops.LwwStamp
import kotlin.test.Test
import kotlin.test.assertTrue

class LwwStampTest {
    @Test
    fun higherLamportWins() {
        assertTrue(LwwStamp(2, byteArrayOf(0)) > LwwStamp(1, byteArrayOf(0x7f)))
    }

    @Test
    fun deviceKeyBreaksTiesUnsigned() {
        assertTrue(LwwStamp(1, byteArrayOf(0x80.toByte())) > LwwStamp(1, byteArrayOf(0x01)))
    }
}
