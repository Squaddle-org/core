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
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)

        val genesis = LogEntry.sign(
            crypto, device.secretKey, room, 0, null, owner.userKey, cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
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
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)
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
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)
        val oldEpochKey = crypto.randomBytes(32)
        val newEpochKey = crypto.randomBytes(32)

        val genesis = LogEntry.sign(
            crypto, device.secretKey, room, 0, null, owner.userKey, cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
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
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)

        val genesis = LogEntry.sign(
            crypto, device.secretKey, room, 0, null, owner.userKey, cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
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

    @Test
    fun createRoomPersistsGenesisLocallyAndRegistersEpoch0Key() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)

        var postRoomCalls = 0
        val mockEngine = MockEngine { request ->
            postRoomCalls++
            respond("""{"index":0,"rts":500}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
        }
        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(mockEngine))

        val outcome = sync.createRoom(room, roomNonce)
        assertEquals(PushOutcome.Ok, outcome)
        assertEquals(1, postRoomCalls)
        assertEquals(1, store.logEntriesFrom(room, 0L).size)
        assertTrue(sync.epochKeyFor(room, 0L) != null)
    }

    @Test
    fun createInviteUploadsAnEnvelopeForAnOpenInviteAndStoresTheSecret() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)

        var putEnvelopeCalls = 0
        val mockEngine = MockEngine { request ->
            when {
                request.method == HttpMethod.Post && request.url.encodedPath.endsWith("/log") ->
                    respond("""{"index":1,"rts":200}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
                request.method == HttpMethod.Put && request.url.encodedPath.endsWith("/envelope") -> {
                    putEnvelopeCalls++
                    respond(ByteArray(0), HttpStatusCode.NoContent)
                }
                else -> respond(errorBody("invalid"), HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }

        val store = LocalStore(createSqlDriver(":memory:"))
        // Simulate the room already existing locally (this owner created it earlier) so
        // appendLogEntry computes the invite's index as 1, not 0.
        val genesisStub = LogEntry.sign(
            crypto, device.secretKey, room, 0, null, owner.userKey, cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )
        store.insertLogEntry(room, 0L, CanonicalCborCodec.encode(genesisStub.toFullCbor()), 100L)
        store.upsertCursor(room, 0L, 0L)

        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(mockEngine))
        sync.registerEpochKey(room, 0L, crypto.randomBytes(32))
        val inviteId = crypto.randomBytes(16)
        val outcome = sync.createInvite(room, inviteId, requiresApproval = false, roomName = "Board Game Night")

        assertEquals(PushOutcome.Ok, outcome)
        assertEquals(1, putEnvelopeCalls)
        val secrets = store.inviteSecretsFor(room)
        assertEquals(1, secrets.size)
        assertEquals(32, secrets.single().secret.size)
    }

    @Test
    fun joinViaLinkOpensTheEnvelopeRegistersTheEpochKeyAndPushesJoin() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val ownerDevice = crypto.signSeedKeypair(crypto.randomBytes(32))
        val ownerCert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, ownerDevice.publicKey, "Owner Phone", 1L)
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)
        val inviteId = crypto.randomBytes(16)
        val inviteSecret = crypto.randomBytes(32)
        val epochKey = crypto.randomBytes(32)
        val envelope = org.squaddle.core.membership.InviteEnvelope.seal(crypto, inviteSecret, room, inviteId, 0L, epochKey, "Board Game Night")

        val genesis = LogEntry.sign(
            crypto, ownerDevice.secretKey, room, 0, null, owner.userKey, ownerCert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )

        val joiner = UserIdentity.create(crypto)
        val joinerDevice = crypto.signSeedKeypair(crypto.randomBytes(32))
        val joinerCert = DeviceCert.sign(crypto, joiner.signing.secretKey, joiner.userKey, joiner.userBoxKey, joinerDevice.publicKey, "New Phone", 1L)

        var postLogCalls = 0
        val mockEngine = MockEngine { request ->
            when {
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/envelope") ->
                    respond(envelope, HttpStatusCode.OK)
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/log") ->
                    respond(logResponseBytes(listOf(CanonicalCborCodec.encode(genesis.toFullCbor()) to 100L)), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"))
                request.method == HttpMethod.Get && request.url.encodedPath.endsWith("/ops") ->
                    respond(opsResponseBytes(emptyList(), 0L), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/cbor"))
                request.method == HttpMethod.Post && request.url.encodedPath.endsWith("/log") -> {
                    postLogCalls++
                    respond("""{"index":1,"rts":200}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
                }
                else -> respond(errorBody("invalid"), HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }

        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", joiner, joinerDevice, joinerCert, HttpClient(mockEngine))
        val outcome = sync.joinViaLink(room, inviteId, inviteSecret)

        assertEquals(PushOutcome.Ok, outcome)
        assertEquals(1, postLogCalls)
        assertEquals(epochKey.toList(), sync.epochKeyFor(room, 0L)?.toList())
    }

    @Test
    fun pushWithRotationRequiredWaitsWhenLocalIdentityIsAPlainMember() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val ownerDevice = crypto.signSeedKeypair(crypto.randomBytes(32))
        val ownerCert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, ownerDevice.publicKey, "Owner Phone", 1L)
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)

        val member = UserIdentity.create(crypto)
        val memberDevice = crypto.signSeedKeypair(crypto.randomBytes(32))
        val memberCert = DeviceCert.sign(crypto, member.signing.secretKey, member.userKey, member.userBoxKey, memberDevice.publicKey, "Member Phone", 1L)

        val genesis = LogEntry.sign(
            crypto, ownerDevice.secretKey, room, 0, null, owner.userKey, ownerCert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )
        val inviteId = crypto.randomBytes(16)
        val inviteCreate = LogEntry.sign(
            crypto, ownerDevice.secretKey, room, 1, genesis.entryHash(crypto), owner.userKey, ownerCert, EntryType.INVITE_CREATE,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(inviteId), 3L to CborValue.Bool(false), 4L to CborValue.Text("member"))),
            2L,
        )
        val join = LogEntry.sign(
            crypto, memberDevice.secretKey, room, 2, inviteCreate.entryHash(crypto), member.userKey, memberCert, EntryType.JOIN,
            CborValue.Map(mapOf(0L to CborValue.Bytes(inviteId))),
            3L,
        )

        val store = LocalStore(createSqlDriver(":memory:"))
        for ((idx, entry) in listOf(genesis, inviteCreate, join).withIndex()) {
            store.insertLogEntry(room, idx.toLong(), CanonicalCborCodec.encode(entry.toFullCbor()), 100L + idx)
        }
        store.upsertCursor(room, 2L, 0L)

        val mockEngine = MockEngine { _ ->
            respond(errorBody("rotation_required"), HttpStatusCode.Conflict, headersOf(HttpHeaders.ContentType, "application/json"))
        }
        val sync = SyncClient(crypto, store, "relay.example.org", member, memberDevice, memberCert, HttpClient(mockEngine))
        sync.registerEpochKey(room, 0L, crypto.randomBytes(32))
        assertTrue(sync.enqueueOp(room, OpBody.IdeaCreate(crypto.randomBytes(16), "x", null, emptyList())))

        val outcome = sync.push(room)
        assertEquals(PushOutcome.WaitingForRotation, outcome)
        // the op stays queued - the member didn't lose it, it's just waiting for an admin.
        assertEquals(1, store.outboxFor(room).size)
    }

    @Test
    fun pushWithRotationRequiredAutoRotatesWhenLocalIdentityIsOwner() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val ownerDevice = crypto.signSeedKeypair(crypto.randomBytes(32))
        val ownerCert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, ownerDevice.publicKey, "Owner Phone", 1L)
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)

        val genesis = LogEntry.sign(
            crypto, ownerDevice.secretKey, room, 0, null, owner.userKey, ownerCert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )

        val store = LocalStore(createSqlDriver(":memory:"))
        store.insertLogEntry(room, 0L, CanonicalCborCodec.encode(genesis.toFullCbor()), 100L)
        store.upsertCursor(room, 0L, 0L)

        var postOpsAttempts = 0
        var postLogAttempts = 0
        val mockEngine = MockEngine { request ->
            when {
                request.method == HttpMethod.Post && request.url.encodedPath.endsWith("/ops") -> {
                    postOpsAttempts++
                    if (postOpsAttempts == 1) {
                        respond(errorBody("rotation_required"), HttpStatusCode.Conflict, headersOf(HttpHeaders.ContentType, "application/json"))
                    } else {
                        respond("""{"cursors":[1]}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
                    }
                }
                request.method == HttpMethod.Post && request.url.encodedPath.endsWith("/log") -> {
                    postLogAttempts++
                    respond("""{"index":1,"rts":200}""".encodeToByteArray(), HttpStatusCode.Created, headersOf(HttpHeaders.ContentType, "application/json"))
                }
                else -> respond(errorBody("invalid"), HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }

        val sync = SyncClient(crypto, store, "relay.example.org", owner, ownerDevice, ownerCert, HttpClient(mockEngine))
        sync.registerEpochKey(room, 0L, crypto.randomBytes(32))
        assertTrue(sync.enqueueOp(room, OpBody.IdeaCreate(crypto.randomBytes(16), "x", null, emptyList())))

        val outcome = sync.push(room)
        assertEquals(PushOutcome.Ok, outcome)
        assertEquals(1, postLogAttempts) // the epochRotate entry owner auto-authored
        assertEquals(2, postOpsAttempts) // rejected once, retried after rotation
        assertEquals(0, store.outboxFor(room).size)
        assertTrue(sync.epochKeyFor(room, 1L) != null) // owner registered its own newly-minted key
    }

    @Test
    fun listMyRoomsDecodesTheRoomListOnSuccess() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.userKey, roomNonce)
        val roomB64 = kotlin.io.encoding.Base64.UrlSafe.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT).encode(room)

        val mockEngine = MockEngine { request ->
            assertTrue(request.url.encodedPath.endsWith("/rooms"))
            respond(
                """[{"roomId":"$roomB64","relayHost":"relay.squaddle.org"}]""".encodeToByteArray(),
                HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }
        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(mockEngine))

        val outcome = sync.listMyRooms()
        val ok = outcome as ListRoomsOutcome.Ok
        assertEquals(1, ok.rooms.size)
        assertEquals(room.toList(), ok.rooms.single().roomId.toList())
        assertEquals("relay.squaddle.org", ok.rooms.single().relayHost)
    }

    @Test
    fun listMyRoomsSurfacesANon200AsError() = runTest {
        val crypto = crypto()
        val owner = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, owner.signing.secretKey, owner.userKey, owner.userBoxKey, device.publicKey, "Phone", 1L)

        val mockEngine = MockEngine { _ ->
            respond(errorBody("forbidden"), HttpStatusCode.Forbidden, headersOf(HttpHeaders.ContentType, "application/json"))
        }
        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, "relay.example.org", owner, device, cert, HttpClient(mockEngine))

        val outcome = sync.listMyRooms()
        val err = outcome as ListRoomsOutcome.Error
        assertEquals(403, err.status)
        assertEquals("forbidden", err.code)
    }
}
