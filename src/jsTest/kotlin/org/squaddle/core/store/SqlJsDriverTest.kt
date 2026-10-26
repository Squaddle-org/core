package org.squaddle.core.store

import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Real browser (Karma + headless Chromium) run against sql.js's actual WASM binary - ADR-0009's
 * SqlDelight browser-persistence gap, closed via [SqlJsDriver] (no official sync browser driver
 * exists). Locally verified end to end via webclient's Vitest (Node/V8, same engine); this is
 * the permanent test-of-record for CI, which has a real browser this sandbox didn't. */
class SqlJsDriverTest {

    @BeforeTest
    fun preload() = runTest {
        if (sqlJsStatic == null) {
            preloadSqlJsDriver { fileName -> "/node_modules/sql.js/dist/$fileName" }
        }
    }

    private fun newStore(): LocalStore = LocalStore(createSqlDriver(":memory:"))

    @Test
    fun insertAndReadBackLogEntries() {
        val store = newStore()
        val room = ByteArray(32) { it.toByte() }

        store.insertLogEntry(room, 0L, byteArrayOf(1, 2, 3), 100L)
        store.insertLogEntry(room, 1L, byteArrayOf(4, 5, 6), 200L)

        val entries = store.logEntriesFrom(room, 0L)
        assertEquals(2, entries.size)
        assertContentEquals(byteArrayOf(1, 2, 3), entries[0].entry_cbor)
        assertContentEquals(byteArrayOf(4, 5, 6), entries[1].entry_cbor)
        assertEquals(1L, store.maxLogIndex(room))
    }

    @Test
    fun maxLogIndexIsNullForAnUnknownRoom() {
        val store = newStore()
        assertNull(store.maxLogIndex(ByteArray(32)))
    }

    @Test
    fun cursorsRoundTrip() {
        val store = newStore()
        val room = ByteArray(32) { 7 }
        store.upsertCursor(room, 5L, 10L)
        val cursor = store.cursorFor(room)
        assertEquals(5L, cursor?.last_log_index)
        assertEquals(10L, cursor?.last_ops_cursor)

        store.upsertCursor(room, 6L, 11L)
        val updated = store.cursorFor(room)
        assertEquals(6L, updated?.last_log_index)
        assertEquals(11L, updated?.last_ops_cursor)
    }
}
