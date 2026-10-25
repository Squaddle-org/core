package org.squaddle.core.store

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class LocalStoreTest {

    private fun newStore(): LocalStore = LocalStore(createSqlDriver(":memory:"))

    @Test
    fun logEntryRoundTrips() {
        val store = newStore()
        val room = ByteArray(32) { it.toByte() }
        store.insertLogEntry(room, 0L, byteArrayOf(1, 2, 3), 1_700_000_000L)
        store.insertLogEntry(room, 1L, byteArrayOf(4, 5, 6), 1_700_000_100L)

        val entries = store.logEntriesFrom(room, 0L)
        assertEquals(2, entries.size)
        assertContentEquals(byteArrayOf(1, 2, 3), entries[0].entry_cbor)
        assertEquals(1L, entries[1].idx)
        assertEquals(1L, store.maxLogIndex(room))
    }

    @Test
    fun maxLogIndexIsNullForAnEmptyRoom() {
        val store = newStore()
        assertNull(store.maxLogIndex(ByteArray(32)))
    }

    @Test
    fun opRoundTrips() {
        val store = newStore()
        val room = ByteArray(32) { it.toByte() }
        val device = ByteArray(32) { 9 }
        store.insertOp(room, 1L, ByteArray(32) { 1 }, device, 1L, byteArrayOf(10, 20))
        store.insertOp(room, 2L, ByteArray(32) { 2 }, device, 2L, byteArrayOf(30, 40))

        val afterZero = store.opsAfter(room, 0L)
        assertEquals(2, afterZero.size)
        val afterOne = store.opsAfter(room, 1L)
        assertEquals(1, afterOne.size)
        assertContentEquals(byteArrayOf(30, 40), afterOne[0].envelope_cbor)
        assertEquals(2L, store.maxOpsCursor(room))
    }

    @Test
    fun cursorUpsertOverwritesPreviousValue() {
        val store = newStore()
        val room = ByteArray(32) { it.toByte() }
        store.upsertCursor(room, 3L, 10L)
        val first = store.cursorFor(room)!!
        assertEquals(3L, first.last_log_index)
        assertEquals(10L, first.last_ops_cursor)

        store.upsertCursor(room, 5L, 20L)
        val second = store.cursorFor(room)!!
        assertEquals(5L, second.last_log_index)
        assertEquals(20L, second.last_ops_cursor)
    }

    @Test
    fun cursorForUnknownRoomIsNull() {
        val store = newStore()
        assertNull(store.cursorFor(ByteArray(32)))
    }

    @Test
    fun deviceSeqUpsertOverwritesPreviousValue() {
        val store = newStore()
        val room = ByteArray(32) { it.toByte() }
        val device = ByteArray(32) { 9 }
        store.upsertDeviceSeq(room, device, 1L)
        store.upsertDeviceSeq(room, device, 2L)

        val seqs = store.deviceSeqsFor(room)
        assertEquals(1, seqs.size)
        assertEquals(2L, seqs[0].seq)
    }

    @Test
    fun outboxDrainsInLocalOrderAndSupportsReplaceAndDelete() {
        val store = newStore()
        val room = ByteArray(32) { it.toByte() }
        store.insertOutbox(room, 1L, 0L, 1L, 1L, ByteArray(24), byteArrayOf(10), byteArrayOf(1))
        store.insertOutbox(room, 2L, 0L, 2L, 2L, ByteArray(24), byteArrayOf(20), byteArrayOf(2))
        store.insertOutbox(room, 3L, 0L, 3L, 3L, ByteArray(24), byteArrayOf(30), byteArrayOf(3))

        assertEquals(listOf(1, 2, 3), store.outboxFor(room).map { it.envelope_cbor[0].toInt() })
        assertEquals(3L, store.maxOutboxLocalOrder(room))

        store.replaceOutboxEnvelope(room, 2L, 1L, ByteArray(24) { 9 }, byteArrayOf(99))
        assertEquals(listOf(1, 99, 3), store.outboxFor(room).map { it.envelope_cbor[0].toInt() })

        store.deleteOutboxEntry(room, 1L)
        assertEquals(listOf(99, 3), store.outboxFor(room).map { it.envelope_cbor[0].toInt() })
    }

    @Test
    fun maxOutboxLocalOrderIsNullWhenEmpty() {
        val store = newStore()
        assertNull(store.maxOutboxLocalOrder(ByteArray(32)))
    }

    @Test
    fun separateRoomsAreIndependent() {
        val store = newStore()
        val roomA = ByteArray(32) { 1 }
        val roomB = ByteArray(32) { 2 }
        store.insertLogEntry(roomA, 0L, byteArrayOf(1), 1L)
        store.insertLogEntry(roomB, 0L, byteArrayOf(2), 1L)

        assertEquals(1, store.logEntriesFrom(roomA, 0L).size)
        assertEquals(1, store.logEntriesFrom(roomB, 0L).size)
        assertContentEquals(byteArrayOf(1), store.logEntriesFrom(roomA, 0L)[0].entry_cbor)
    }
}
