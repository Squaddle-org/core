package org.squaddle.core.sync

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.EpochKeys
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.roomId
import org.squaddle.core.ops.OpBody
import org.squaddle.core.ops.encode
import org.squaddle.core.store.LocalStore
import org.squaddle.core.store.createSqlDriver
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** PROTOCOL.md §4/§5 behavioral tests for [SyncClient] against a [MockEngine] fake relay - the
 * real cross-process check (a real relay binary) is the integration test, M3's final step. */
class SyncClientTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private fun logResponseBytes(entries: List<Pair<ByteArray, Long>>): ByteArray =
        CanonicalCborCodec.encode(
            CborValue.Array(entries.map { (cbor, rts) -> CborValue.Map(mapOf(0L to CborValue.Bytes(cbor), 1L to CborValue.UInt(rts))) }),
        )

    private fun opsResponseBytes(ops: List<Pair<Long, ByteArray>>, next: Long): ByteArray =
        CanonicalCborCodec.encode(
            CborValue.Map(
                mapOf(
                    0L to CborValue.Array(ops.map { (cursor, env) -> CborValue.Map(mapOf(0L to CborValue.UInt(cursor), 1L to CborValue.Bytes(env))) }),
                    1L to CborValue.UInt(next),
                ),
            ),
        )

    private fun errorBody(code: String, message: String = "error"): ByteArray =
        """{"code":"$code","message":"$message"}""".encodeToByteArray()

    @Test
    fun pullAppliesLogAndOpsIntoLocalStoreAndAdvancesCursor() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)
        val room = roomId(crypto, owner.userKey, crypto.randomBytes(16))

        val genesis = LogEntry.sign(
            crypto, device.secretKey, room, 0, null, owner.userKey, cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(ByteArray(16)), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )
        val epochKey = crypto.randomBytes(32)
        val opEnv = org.squaddle.core.ops.OpEnvelope.create(
            crypto, device.secretKey, epochKey, room, 0L, owner.userKey, device.publicKey, 1L, 1L,
            OpBody.IdeaCreate(crypto.randomBytes(16), "Camping trip", null, emptyList()),
        )

        var logRequests = 0
        var opsRequests = 0
        val mockEngine = MockEngine { request ->
            when {
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/log") -> {
                    logRequests++
                    respond(logResponseBytes(listOf(CanonicalCborCodec.encode(genesis.toFullCbor()) to 100L)), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"))
                }
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/ops") -> {
                    opsRequests++
                    respond(opsResponseBytes(listOf(1L to CanonicalCborCodec.encode(opEnv.toFullCbor())), 1L), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"))
                }
                else -> respond(errorBody("invalid"), HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }

        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(mockEngine))
        val outcome = sync.pull(room)

        assertEquals(SyncOutcome.Ok, outcome)
        assertEquals(1, logRequests)
        assertEquals(1, opsRequests)
        assertEquals(1, store.logEntriesFrom(room, 0L).size)
        assertEquals(1, store.opsAfter(room, 0L).size)
        val cursor = store.cursorFor(room)!!
        assertEquals(0L, cursor.last_log_index)
        assertEquals(1L, cursor.last_ops_cursor)
    }

    @Test
    fun pushDrainsOutboxOnSuccess() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)
        val room = roomId(crypto, owner.userKey, crypto.randomBytes(16))
        val epochKey = crypto.randomBytes(32)

        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(MockEngine { _ ->
            respond("""{"cursors":[1]}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
        }))
        sync.registerEpochKey(room, 0L, epochKey)
        assertTrue(sync.enqueueOp(room, OpBody.IdeaCreate(crypto.randomBytes(16), "x", null, emptyList())))

        assertEquals(1, store.outboxFor(room).size)
        val outcome = sync.push(room)
        assertEquals(PushOutcome.Ok, outcome)
        assertEquals(0, store.outboxFor(room).size)
    }

    @Test
    fun pushRetriesOnceAfterStaleEpochThenSucceeds() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)
        val room = roomId(crypto, owner.userKey, crypto.randomBytes(16))
        val oldEpochKey = crypto.randomBytes(32)
        val newEpochKey = crypto.randomBytes(32)

        val genesis = LogEntry.sign(
            crypto, device.secretKey, room, 0, null, owner.userKey, cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(ByteArray(16)), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )
        val sealedForOwner = EpochKeys.seal(crypto, owner.userBoxKey, room, 1L, newEpochKey)
        val rotateEntry = LogEntry.sign(
            crypto, device.secretKey, room, 1, genesis.entryHash(crypto), owner.userKey, cert, EntryType.EPOCH_ROTATE,
            CborValue.Map(
                mapOf(
                    0L to CborValue.UInt(1L),
                    1L to CborValue.Array(listOf(CborValue.Map(mapOf(0L to CborValue.Bytes(owner.userKey), 1L to CborValue.Bytes(sealedForOwner))))),
                ),
            ),
            2L,
        )

        var postOpsAttempts = 0
        val mockEngine = MockEngine { request ->
            when {
                request.method == HttpMethod.Post && request.url.encodedPath.endsWith("/ops") -> {
                    postOpsAttempts++
                    if (postOpsAttempts == 1) {
                        respond(errorBody("stale_epoch"), HttpStatusCode.Conflict, headersOf(HttpHeaders.ContentType, "application/json"))
                    } else {
                        respond("""{"cursors":[1]}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
                    }
                }
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/log") -> {
                    respond(
                        logResponseBytes(listOf(CanonicalCborCodec.encode(genesis.toFullCbor()) to 100L, CanonicalCborCodec.encode(rotateEntry.toFullCbor()) to 200L)),
                        HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"),
                    )
                }
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/ops") -> {
                    respond(opsResponseBytes(emptyList(), 0L), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"))
                }
                else -> respond(errorBody("invalid"), HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }

        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(mockEngine))
        sync.registerEpochKey(room, 0L, oldEpochKey)
        assertTrue(sync.enqueueOp(room, OpBody.IdeaCreate(crypto.randomBytes(16), "x", null, emptyList())))

        val before = store.outboxFor(room).single()
        assertEquals(0L, before.epoch)

        val outcome = sync.push(room)
        assertEquals(PushOutcome.Ok, outcome)
        assertEquals(0, store.outboxFor(room).size)
        assertEquals(2, postOpsAttempts)
    }

    @Test
    fun appendLogEntryRetriesWithFreshHeadAfterStaleHead() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)
        val room = roomId(crypto, owner.userKey, crypto.randomBytes(16))

        val genesis = LogEntry.sign(
            crypto, device.secretKey, room, 0, null, owner.userKey, cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(ByteArray(16)), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )

        var postLogAttempts = 0
        val mockEngine = MockEngine { request ->
            when {
                request.method == HttpMethod.Post && request.url.encodedPath.endsWith("/log") -> {
                    postLogAttempts++
                    if (postLogAttempts == 1) {
                        respond(errorBody("stale_head"), HttpStatusCode.Conflict, headersOf(HttpHeaders.ContentType, "application/json"))
                    } else {
                        respond("""{"index":1,"rts":300}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
                    }
                }
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/log") -> {
                    respond(logResponseBytes(listOf(CanonicalCborCodec.encode(genesis.toFullCbor()) to 100L)), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"))
                }
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/ops") -> {
                    respond(opsResponseBytes(emptyList(), 0L), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"))
                }
                else -> respond(errorBody("invalid"), HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }

        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(mockEngine))

        var builtIndices = mutableListOf<Long>()
        val outcome = sync.appendLogEntry(room) { index, prev ->
            builtIndices.add(index)
            LogEntry.sign(crypto, device.secretKey, room, index, prev, owner.userKey, cert, EntryType.ROOM_SETTINGS, CborValue.Map(emptyMap()), 400L)
        }

        assertEquals(PushOutcome.Ok, outcome)
        assertEquals(2, postLogAttempts)
        // first attempt built against index 0 (no local history yet); the stale_head forces a
        // pull that discovers genesis already occupies index 0, so the retry must build index 1.
        assertEquals(listOf(0L, 1L), builtIndices)
    }
}
