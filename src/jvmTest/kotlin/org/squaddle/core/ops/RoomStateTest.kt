package org.squaddle.core.ops

import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipState
import org.squaddle.core.membership.MembershipStateImpl
import org.squaddle.core.membership.StoredEntry
import org.squaddle.core.membership.roomId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * PROTOCOL.md §4.2 round-trip + authorization-reject tests for [RoomState], plus a property test
 * confirming [RoomState.fold] is order-independent.
 */
class RoomStateTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private class Actor(val identity: UserIdentity, val deviceKey: KeyPair, val cert: DeviceCert)

    private suspend fun actor(crypto: Crypto, label: String = "device"): Actor {
        val identity = UserIdentity.create(crypto)
        val deviceKey = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, deviceKey.publicKey, label, 1L)
        return Actor(identity, deviceKey, cert)
    }

    /** Drives a membership log + the content-plane ops layered on top of it, for one room. */
    private class Room(val crypto: Crypto, val roomId: ByteArray, val epochKey: ByteArray) {
        var state: MembershipState = MembershipStateImpl.empty(crypto)
        var index = 0L
        var head: ByteArray? = null
        val entries = mutableListOf<StoredEntry>()
        var epoch = 0L
        var lamport = 0L

        private fun build(actor: Actor, type: EntryType, body: CborValue.Map): LogEntry =
            LogEntry.sign(crypto, actor.deviceKey.secretKey, roomId, index, head, actor.identity.userKey, actor.cert, type, body, 1_700_000_000L + index)

        fun apply(actor: Actor, type: EntryType, body: CborValue.Map) {
            val entry = build(actor, type, body)
            val stored = StoredEntry(entry, 1_700_000_500L)
            state = state.apply(stored).getOrThrow()
            entries += stored
            index = entry.index + 1
            head = entry.entryHash(crypto)
            epoch = state.epoch
        }

        fun history(): MembershipHistory = MembershipHistory.build(entries, MembershipStateImpl.empty(crypto))

        fun op(actor: Actor, body: OpBody, seq: Long = 1L): OpEnvelope {
            lamport += 1
            return OpEnvelope.create(
                crypto = crypto, deviceSecretKey = actor.deviceKey.secretKey, epochKey = epochKey,
                room = roomId, epoch = epoch, author = actor.identity.userKey, device = actor.deviceKey.publicKey,
                seq = seq, lamport = lamport, body = body,
            )
        }
    }

    private fun genesisBody(nonce: ByteArray) = CborValue.Map(linkedMapOf(0L to CborValue.Bytes(nonce), 1L to CborValue.Text("relay.squaddle.org"), 2L to CborValue.Bytes(ByteArray(48))))
    private fun inviteCreateBody(inviteId: ByteArray) = CborValue.Map(linkedMapOf(0L to CborValue.Bytes(inviteId), 3L to CborValue.Bool(false), 4L to CborValue.Text("member")))
    private fun joinBody(inviteId: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(inviteId)))
    private fun setRoleBody(user: ByteArray, role: String) = CborValue.Map(mapOf(0L to CborValue.Bytes(user), 1L to CborValue.Text(role)))
    private fun removeBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user)))
    private fun epochRotateBody(epoch: Long, users: List<ByteArray>) = CborValue.Map(
        mapOf(0L to CborValue.UInt(epoch), 1L to CborValue.Array(users.map { CborValue.Map(mapOf(0L to CborValue.Bytes(it), 1L to CborValue.Bytes(ByteArray(48)))) })),
    )

    private fun open(crypto: Crypto, env: OpEnvelope, epochKey: ByteArray, certs: List<Actor>): OpBody? {
        val result = env.open(crypto, epochKey) { d -> certs.firstOrNull { it.deviceKey.publicKey.contentEquals(d) }?.cert }
        return (result as? OpOpenResult.Ok)?.body
    }

    /** Sets up: owner + member, both joined, one room, one epoch (0). */
    private suspend fun setUpOwnerAndMember(crypto: Crypto): Triple<Room, Actor, Actor> {
        val owner = actor(crypto, "Owner")
        val member = actor(crypto, "Member")
        val nonce = crypto.randomBytes(16)
        val room = Room(crypto, roomId(crypto, owner.identity.userKey, nonce), crypto.randomBytes(32))
        room.apply(owner, EntryType.GENESIS, genesisBody(nonce))
        val inviteId = crypto.randomBytes(16)
        room.apply(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId))
        room.apply(member, EntryType.JOIN, joinBody(inviteId))
        return Triple(room, owner, member)
    }

    @Test
    fun ideaCreateByMemberIsAuthorized() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val ideaId = crypto.randomBytes(16)
        val env = room.op(member, OpBody.IdeaCreate(ideaId, "Camping trip", null, emptyList()))
        val body = open(crypto, env, room.epochKey, listOf(owner, member))!!

        val state = RoomState.fold(listOf(env to body), room.history())
        val idea = state.ideas.values.single()
        assertEquals("Camping trip", idea.title)
        assertTrue(idea.createdBy.contentEquals(member.identity.userKey))
    }

    @Test
    fun ideaSetByNonAuthorNonAdminIsRejected() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val other = actor(crypto, "Other")
        val inviteId2 = crypto.randomBytes(16)
        room.apply(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId2))
        room.apply(other, EntryType.JOIN, joinBody(inviteId2))

        val ideaId = crypto.randomBytes(16)
        val createEnv = room.op(member, OpBody.IdeaCreate(ideaId, "Camping trip", null, emptyList()))
        val setEnv = room.op(other, OpBody.IdeaSet(ideaId, "title", "Hijacked title"))
        val certs = listOf(owner, member, other)
        val ops = listOfNotNull(
            open(crypto, createEnv, room.epochKey, certs)?.let { createEnv to it },
            open(crypto, setEnv, room.epochKey, certs)?.let { setEnv to it },
        )

        val state = RoomState.fold(ops, room.history())
        assertEquals("Camping trip", state.ideas.values.single().title) // unauthorized edit silently ignored
    }

    @Test
    fun ideaSetByAdminIsAuthorized() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val admin = actor(crypto, "Admin")
        val inviteId2 = crypto.randomBytes(16)
        room.apply(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId2))
        room.apply(admin, EntryType.JOIN, joinBody(inviteId2))
        room.apply(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin"))

        val ideaId = crypto.randomBytes(16)
        val createEnv = room.op(member, OpBody.IdeaCreate(ideaId, "Camping trip", null, emptyList()))
        val setEnv = room.op(admin, OpBody.IdeaSet(ideaId, "title", "Admin-edited title"))
        val certs = listOf(owner, member, admin)
        val ops = listOf(createEnv, setEnv).map { it to open(crypto, it, room.epochKey, certs)!! }

        val state = RoomState.fold(ops, room.history())
        assertEquals("Admin-edited title", state.ideas.values.single().title)
    }

    @Test
    fun ideaDeleteTombstoneWinsOverALowerStampedEdit() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val ideaId = crypto.randomBytes(16)
        val createEnv = room.op(member, OpBody.IdeaCreate(ideaId, "Camping trip", null, emptyList()))
        val deleteEnv = room.op(member, OpBody.IdeaDelete(ideaId)) // higher lamport than create
        val certs = listOf(owner, member)
        val ops = listOf(createEnv, deleteEnv).map { it to open(crypto, it, room.epochKey, certs)!! }

        val state = RoomState.fold(ops, room.history())
        assertTrue(state.ideas.values.single().deleted)
    }

    @Test
    fun voteSetIsIndependentPerAuthor() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val ideaId = crypto.randomBytes(16)
        val createEnv = room.op(member, OpBody.IdeaCreate(ideaId, "x", null, emptyList()))
        val ownerVote = room.op(owner, OpBody.VoteSet(ideaId, 1))
        val memberVote = room.op(member, OpBody.VoteSet(ideaId, -1))
        val certs = listOf(owner, member)
        val ops = listOf(createEnv, ownerVote, memberVote).map { it to open(crypto, it, room.epochKey, certs)!! }

        val state = RoomState.fold(ops, room.history())
        assertEquals(2, state.votes.size)
        val ownerKey = ideaId.joinToString("") { "%02x".format(it) } + owner.identity.userKey.joinToString("") { "%02x".format(it) }
        val memberKey = ideaId.joinToString("") { "%02x".format(it) } + member.identity.userKey.joinToString("") { "%02x".format(it) }
        assertEquals(1, state.votes[ownerKey]?.value)
        assertEquals(-1, state.votes[memberKey]?.value)
    }

    @Test
    fun commentDeleteByNonAuthorNonAdminIsRejected() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val other = actor(crypto, "Other")
        val inviteId2 = crypto.randomBytes(16)
        room.apply(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId2))
        room.apply(other, EntryType.JOIN, joinBody(inviteId2))

        val ideaId = crypto.randomBytes(16)
        val commentId = crypto.randomBytes(16)
        val createIdea = room.op(member, OpBody.IdeaCreate(ideaId, "x", null, emptyList()))
        val addComment = room.op(member, OpBody.CommentAdd(commentId, ideaId, "nice"))
        val deleteByOther = room.op(other, OpBody.CommentDelete(commentId))
        val certs = listOf(owner, member, other)
        val ops = listOf(createIdea, addComment, deleteByOther).map { it to open(crypto, it, room.epochKey, certs)!! }

        val state = RoomState.fold(ops, room.history())
        assertTrue(!state.comments.values.single().deleted)
    }

    @Test
    fun eventCreateByPlainMemberIsAuthorizedByDefault() = runTest {
        // §3.3 row 11 field 1 (membersCanCreateEvents) defaults to true - no roomSettings entry
        // needed for a plain member to create an event.
        val crypto = crypto()
        val (room, _, member) = setUpOwnerAndMember(crypto)
        val eventId = crypto.randomBytes(16)
        val env = room.op(member, OpBody.EventCreate(eventId, null, "Game night", 1_700_000_000L, null, "UTC", null, false))
        val body = open(crypto, env, room.epochKey, listOf(member))!!

        val state = RoomState.fold(listOf(env to body), room.history())
        assertEquals("Game night", state.events.values.single().title)
    }

    @Test
    fun eventCreateByPlainMemberIsRejectedWhenSettingDisabled() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        room.apply(owner, EntryType.ROOM_SETTINGS, CborValue.Map(mapOf(1L to CborValue.Bool(false))))

        val eventId = crypto.randomBytes(16)
        val env = room.op(member, OpBody.EventCreate(eventId, null, "Game night", 1_700_000_000L, null, "UTC", null, false))
        val body = open(crypto, env, room.epochKey, listOf(member))!!

        val state = RoomState.fold(listOf(env to body), room.history())
        assertTrue(state.events.isEmpty())
    }

    @Test
    fun eventCreateAuthorizationIsEvaluatedAtOpsEpoch() = runTest {
        // A member's op stamped at epoch 0 (membersCanCreateEvents still true there) must stay
        // authorized even after the setting is later disabled at epoch 1 - same epoch-pinning
        // RoomStateTest already relies on for roleAt().
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val eventId = crypto.randomBytes(16)
        val env = room.op(member, OpBody.EventCreate(eventId, null, "Game night", 1_700_000_000L, null, "UTC", null, false))
        val body = open(crypto, env, room.epochKey, listOf(member))!!

        room.apply(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, member.identity.userKey)))
        room.apply(owner, EntryType.ROOM_SETTINGS, CborValue.Map(mapOf(1L to CborValue.Bool(false))))

        val state = RoomState.fold(listOf(env to body), room.history())
        assertEquals("Game night", state.events.values.single().title)
    }

    @Test
    fun eventCreateByAdminIsAuthorized() = runTest {
        val crypto = crypto()
        val (room, owner, _) = setUpOwnerAndMember(crypto)
        val eventId = crypto.randomBytes(16)
        val env = room.op(owner, OpBody.EventCreate(eventId, null, "Game night", 1_700_000_000L, null, "UTC", null, false))
        val body = open(crypto, env, room.epochKey, listOf(owner))!!

        val state = RoomState.fold(listOf(env to body), room.history())
        assertEquals("Game night", state.events.values.single().title)
    }

    @Test
    fun rsvpAndProfileAreOwnOnly() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val eventId = crypto.randomBytes(16)
        val createEvent = room.op(owner, OpBody.EventCreate(eventId, null, "Game night", 1_700_000_000L, null, "UTC", null, false))
        val rsvp = room.op(member, OpBody.RsvpSet(eventId, "yes"))
        val profile = room.op(member, OpBody.ProfileSet("Mem", "🙂"))
        val certs = listOf(owner, member)
        val ops = listOf(createEvent, rsvp, profile).map { it to open(crypto, it, room.epochKey, certs)!! }

        val state = RoomState.fold(ops, room.history())
        val memberKey = member.identity.userKey.joinToString("") { "%02x".format(it) }
        assertEquals("yes", state.rsvps.values.single().value)
        assertEquals("Mem", state.profiles[memberKey]?.displayName)
    }

    @Test
    fun unknownOpTypeIsIgnoredNotRejected() = runTest {
        val crypto = crypto()
        val (room, owner, member) = setUpOwnerAndMember(crypto)
        val env = room.op(member, OpBody.Unknown("future.type"))
        val body = open(crypto, env, room.epochKey, listOf(owner, member))!!
        // Must not throw, and must leave state unchanged - ignored, not rejected.
        val state = RoomState.fold(listOf(env to body), room.history())
        assertEquals(RoomState(), state)
    }

    @Test
    fun opAtAPastEpochAuthorizesAgainstThatEpochsRosterNotTheCurrentOne() = runTest {
        val crypto = crypto()
        val owner = actor(crypto, "Owner")
        val admin = actor(crypto, "Admin")
        val nonce = crypto.randomBytes(16)
        val room = Room(crypto, roomId(crypto, owner.identity.userKey, nonce), crypto.randomBytes(32))
        room.apply(owner, EntryType.GENESIS, genesisBody(nonce))
        val inviteId = crypto.randomBytes(16)
        room.apply(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId))
        room.apply(admin, EntryType.JOIN, joinBody(inviteId))
        room.apply(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin"))

        val ideaId = crypto.randomBytes(16)
        val createEnv = room.op(owner, OpBody.IdeaCreate(ideaId, "Original", null, emptyList()))
        // admin edits owner's idea while still epoch 0, holding admin.
        val editEnv = room.op(admin, OpBody.IdeaSet(ideaId, "title", "Edited by admin"))

        // Epoch 0 closes (both members still present, nobody removed) and only THEN, in the new
        // epoch, is admin demoted back to a plain member.
        room.apply(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, admin.identity.userKey)))
        room.apply(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "member"))

        val certs = listOf(owner, admin)
        val ops = listOf(createEnv, editEnv).map { it to open(crypto, it, room.epochKey, certs)!! }
        val state = RoomState.fold(ops, room.history())

        // The edit must still have been authorized: admin held admin for the entirety of epoch 0
        // (the edit's epoch), which is all that matters - the demotion only ever took effect in
        // epoch 1, strictly after epoch 0's own snapshot had already closed.
        assertEquals("Edited by admin", state.ideas.values.single().title)
    }

    @Test
    fun propertyFoldIsOrderIndependent() = runTest {
        checkAll(Arb.int(3..8)) { opCount ->
            val crypto = crypto()
            val (room, owner, member) = setUpOwnerAndMember(crypto)
            val actors = listOf(owner, member)
            val ideaId = crypto.randomBytes(16)
            val createEnv = room.op(member, OpBody.IdeaCreate(ideaId, "Seed idea", null, emptyList()))

            val generated = (1..opCount).map { i ->
                val author = actors[i % actors.size]
                when (i % 3) {
                    0 -> room.op(author, OpBody.VoteSet(ideaId, (i % 3) - 1))
                    1 -> room.op(author, OpBody.CommentAdd(crypto.randomBytes(16), ideaId, "comment $i"))
                    else -> room.op(author, OpBody.ProfileSet("Name$i", null))
                }
            }
            val all = listOf(createEnv) + generated
            val opened = all.map { it to open(crypto, it, room.epochKey, actors)!! }
            val history = room.history()

            val forward = RoomState.fold(opened, history)
            val shuffled = RoomState.fold(opened.shuffled(), history)
            val reversed = RoomState.fold(opened.reversed(), history)

            assertEquals(forward, shuffled)
            assertEquals(forward, reversed)
        }
    }
}
