package org.squaddle.core.ops

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipStateImpl
import org.squaddle.core.membership.StoredEntry
import org.squaddle.core.membership.roomId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SnapshotStateTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private class Actor(val identity: UserIdentity, val deviceKey: org.squaddle.core.crypto.KeyPair, val cert: DeviceCert)

    private suspend fun actor(crypto: Crypto, label: String = "device"): Actor {
        val identity = UserIdentity.create(crypto)
        val deviceKey = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, deviceKey.publicKey, label, 1L)
        return Actor(identity, deviceKey, cert)
    }

    private fun buildRoomState(crypto: Crypto, actor: Actor, room: ByteArray, epochKey: ByteArray): RoomState {
        val ideaId = crypto.randomBytes(16)
        val commentId = crypto.randomBytes(16)
        val eventId = crypto.randomBytes(16)
        var lamport = 0L
        fun env(body: OpBody): OpEnvelope {
            lamport += 1
            return OpEnvelope.create(crypto, actor.deviceKey.secretKey, epochKey, room, 0L, actor.identity.userKey, actor.deviceKey.publicKey, lamport, lamport, body)
        }
        val ops = listOf(
            env(OpBody.IdeaCreate(ideaId, "Camping trip", "long weekend", listOf("outdoors"))),
            env(OpBody.VoteSet(ideaId, 1)),
            env(OpBody.CommentAdd(commentId, ideaId, "nice idea")),
            env(OpBody.EventCreate(eventId, ideaId, "Trip kickoff", 1_700_000_000L, 1_700_010_000L, "UTC", "Trailhead", false)),
            env(OpBody.RsvpSet(eventId, "yes")),
            env(OpBody.ProfileSet("Alice", "🏕️")),
        ).map { it to (it.open(crypto, epochKey) { d -> if (d.contentEquals(actor.deviceKey.publicKey)) actor.cert else null } as OpOpenResult.Ok).body }

        // single-owner history: genesis is all this test needs for every op's epoch=0 role lookup.
        val genesis = LogEntry.sign(
            crypto, actor.deviceKey.secretKey, room, 0, null, actor.identity.userKey, actor.cert, EntryType.GENESIS,
            CborValue.Map(linkedMapOf(0L to CborValue.Bytes(ByteArray(16)), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48)))),
            1L,
        )
        val history = MembershipHistory.build(listOf(StoredEntry(genesis, 100L)), MembershipStateImpl.empty(crypto))
        return RoomState.fold(ops, history)
    }

    @Test
    fun payloadRoundTripsThroughCbor() = runTest {
        val crypto = crypto()
        val actor = actor(crypto)
        val roomNonce = ByteArray(16)
        val room = roomId(crypto, actor.identity.userKey, roomNonce)
        val epochKey = crypto.randomBytes(32)
        val state = buildRoomState(crypto, actor, room, epochKey)
        val payload = SnapshotPayload(state, mapOf(actor.deviceKey.publicKey.joinToString("") { "%02x".format(it) } to 6L))

        val decoded = decodeSnapshotPayload(payload.encode())!!
        assertEquals(1, decoded.state.ideas.size)
        assertEquals(1, decoded.state.comments.size)
        assertEquals(1, decoded.state.events.size)
        assertEquals(1, decoded.state.votes.size)
        assertEquals(1, decoded.state.rsvps.size)
        assertEquals(1, decoded.state.profiles.size)
        assertEquals(payload.deviceSeq, decoded.deviceSeq)

        val idea = decoded.state.ideas.values.single()
        assertEquals("Camping trip", idea.title)
        assertEquals(listOf("outdoors"), idea.tags)
        assertTrue(!idea.deleted)
        val event = decoded.state.events.values.single()
        assertEquals("Trip kickoff", event.title)
        assertEquals("yes", decoded.state.rsvps.values.single().value)
        assertEquals("Alice", decoded.state.profiles.values.single().displayName)
    }

    @Test
    fun createAndApplySnapshotRoundTrip() = runTest {
        val crypto = crypto()
        val actor = actor(crypto)
        val roomNonce = ByteArray(16)
        val room = roomId(crypto, actor.identity.userKey, roomNonce)
        val epochKey = crypto.randomBytes(32)
        val state = buildRoomState(crypto, actor, room, epochKey)
        val payload = SnapshotPayload(state, emptyMap())

        val snapshot = createSnapshot(
            crypto = crypto, deviceSecretKey = actor.deviceKey.secretKey, epochKey = epochKey,
            room = room, epoch = 0L, coversUpTo = 6L, author = actor.identity.userKey, device = actor.deviceKey.publicKey,
            payload = payload,
        )
        assertTrue(snapshot.verify(crypto))

        val applied = applySnapshot(crypto, snapshot, epochKey)!!
        assertEquals(1, applied.state.ideas.size)
        assertEquals(payload.state.ideas.keys, applied.state.ideas.keys)
    }

    @Test
    fun applySnapshotReturnsNullForWrongEpochKey() = runTest {
        val crypto = crypto()
        val actor = actor(crypto)
        val roomNonce = ByteArray(16)
        val room = roomId(crypto, actor.identity.userKey, roomNonce)
        val epochKey = crypto.randomBytes(32)
        val wrongKey = crypto.randomBytes(32)
        val payload = SnapshotPayload(RoomState(), emptyMap())

        val snapshot = createSnapshot(
            crypto = crypto, deviceSecretKey = actor.deviceKey.secretKey, epochKey = epochKey,
            room = room, epoch = 0L, coversUpTo = 0L, author = actor.identity.userKey, device = actor.deviceKey.publicKey,
            payload = payload,
        )
        assertNull(applySnapshot(crypto, snapshot, wrongKey))
    }

    @Test
    fun decodeSnapshotPayloadReturnsNullOnMalformedCbor() {
        assertNull(decodeSnapshotPayload(byteArrayOf(0xff.toByte())))
    }
}
