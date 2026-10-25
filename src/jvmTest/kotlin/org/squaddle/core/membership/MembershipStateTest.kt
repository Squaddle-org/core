package org.squaddle.core.membership

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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * PROTOCOL.md §3.3 round-trip + reject tests for [MembershipStateImpl]: one positive case per
 * row plus at least one reject case per row, a full room-lifecycle happy path exercising every
 * entry type in sequence, and a property test over randomly-sized member sets.
 */
class MembershipStateTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private class Actor(val identity: UserIdentity, val deviceKey: KeyPair, val cert: DeviceCert)

    private suspend fun actor(crypto: Crypto, label: String = "device"): Actor {
        val identity = UserIdentity.create(crypto)
        val deviceKey = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, deviceKey.publicKey, label, 1L)
        return Actor(identity, deviceKey, cert)
    }

    /** Drives a single room's log: tracks index/head so callers only ever specify the actor + type + body. */
    private class Room(val crypto: Crypto, val roomId: ByteArray) {
        var state: MembershipState = MembershipStateImpl.empty(crypto)
        var index: Long = 0L
        var head: ByteArray? = null

        fun build(actor: Actor, type: EntryType, body: CborValue.Map): LogEntry =
            LogEntry.sign(crypto, actor.deviceKey.secretKey, roomId, index, head, actor.identity.userKey, actor.cert, type, body, 1_700_000_000L + index)

        /** Applies and asserts success - fails loudly (via getOrThrow) if the entry was unexpectedly rejected. */
        fun apply(entry: LogEntry, rts: Long = 1_700_000_500L): MembershipState {
            state = state.apply(StoredEntry(entry, rts)).getOrThrow()
            index = entry.index + 1
            head = entry.entryHash(crypto)
            return state
        }

        /** Applies and asserts rejection - does NOT advance index/head (a rejected entry is never appended). */
        fun applyAndExpectReject(entry: LogEntry, rts: Long = 1_700_000_500L): RejectReason {
            val result = state.apply(StoredEntry(entry, rts))
            return (result.exceptionOrNull() as? MembershipRejectException)?.reason
                ?: error("expected a MembershipRejectException, got $result")
        }
    }

    // ---- §3.3 body builders ----

    private fun genesisBody(nonce: ByteArray) = CborValue.Map(linkedMapOf(
        0L to CborValue.Bytes(nonce),
        1L to CborValue.Text("relay.squaddle.org"),
        2L to CborValue.Bytes(ByteArray(48)),
    ))

    private fun inviteCreateBody(inviteId: ByteArray, expiresAt: Long? = null, maxUses: Int? = null, requiresApproval: Boolean = false): CborValue.Map {
        val m = linkedMapOf<Long, CborValue>(0L to CborValue.Bytes(inviteId))
        expiresAt?.let { m[1L] = CborValue.UInt(it) }
        maxUses?.let { m[2L] = CborValue.UInt(it.toLong()) }
        m[3L] = CborValue.Bool(requiresApproval)
        m[4L] = CborValue.Text("member")
        return CborValue.Map(m)
    }

    private fun inviteRevokeBody(inviteId: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(inviteId)))
    private fun joinBody(inviteId: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(inviteId)))
    private fun approveBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user), 1L to CborValue.Bytes(ByteArray(32))))
    private fun rejectBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user)))
    private fun removeBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user)))
    private fun leaveBody() = CborValue.Map(emptyMap())
    private fun setRoleBody(user: ByteArray, role: String) = CborValue.Map(mapOf(0L to CborValue.Bytes(user), 1L to CborValue.Text(role)))
    private fun transferOwnerBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user)))
    private fun epochRotateBody(epoch: Long, users: List<ByteArray>) = CborValue.Map(mapOf(
        0L to CborValue.UInt(epoch),
        1L to CborValue.Array(users.map { CborValue.Map(mapOf(0L to CborValue.Bytes(it), 1L to CborValue.Bytes(ByteArray(48)))) }),
    ))
    private fun roomSettingsBody() = CborValue.Map(emptyMap())

    private suspend fun freshRoom(crypto: Crypto, owner: Actor): Room {
        val nonce = crypto.randomBytes(16)
        val room = Room(crypto, roomId(crypto, owner.identity.userKey, nonce))
        room.apply(room.build(owner, EntryType.GENESIS, genesisBody(nonce)))
        return room
    }

    // ---- row 0: genesis ----

    @Test
    fun genesisAcceptedAuthorBecomesOwner() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        assertEquals(Role.OWNER, room.state.roleOf(owner.identity.userKey))
        assertEquals(0L, room.state.epoch)
        assertEquals(1L, room.state.nextIndex)
    }

    @Test
    fun genesisRejectsRoomIdMismatch() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = Room(crypto, crypto.randomBytes(32)) // not derived from owner+nonce
        val entry = room.build(owner, EntryType.GENESIS, genesisBody(crypto.randomBytes(16)))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    @Test
    fun reGenesisAfterRoomExistsIsRejected() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val entry = room.build(owner, EntryType.GENESIS, genesisBody(crypto.randomBytes(16)))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    // ---- row 1/2: invites ----

    @Test
    fun inviteCreateByOwnerAccepted() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val invite0 = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0, requiresApproval = false)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(invite0)))
        assertEquals(Role.MEMBER, room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun membersEnumeratesEveryCurrentUserIncludingPending() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val openMember = actor(crypto)
        val pendingMember = actor(crypto)
        val openInvite = crypto.randomBytes(16)
        val approvalInvite = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(openInvite, requiresApproval = false)))
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(approvalInvite, requiresApproval = true)))
        room.apply(room.build(openMember, EntryType.JOIN, joinBody(openInvite)))
        room.apply(room.build(pendingMember, EntryType.JOIN, joinBody(approvalInvite)))

        val members = room.state.members().associate { it.user.toList() to it.role }
        assertEquals(3, members.size)
        assertEquals(Role.OWNER, members[owner.identity.userKey.toList()])
        assertEquals(Role.MEMBER, members[openMember.identity.userKey.toList()])
        assertEquals(Role.PENDING, members[pendingMember.identity.userKey.toList()])
    }

    @Test
    fun inviteCreateRejectsNonAdminAuthor() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val invite0 = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0, requiresApproval = false)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(invite0)))
        val invite1 = crypto.randomBytes(16)
        val entry = room.build(member, EntryType.INVITE_CREATE, inviteCreateBody(invite1))
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(entry))
    }

    @Test
    fun inviteCreateRejectsDuplicateId() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        val dup = room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(dup))
    }

    @Test
    fun inviteRevokeByAdminAccepted() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(owner, EntryType.INVITE_REVOKE, inviteRevokeBody(inviteId)))
        assertEquals(true, room.state.invites().single { it.id.contentEquals(inviteId) }.revoked)
    }

    @Test
    fun inviteRevokeRejectsNonAdminAuthor() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val joinInvite = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(joinInvite)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(joinInvite)))
        val entry = room.build(member, EntryType.INVITE_REVOKE, inviteRevokeBody(joinInvite))
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(entry))
    }

    // ---- row 3: join ----

    @Test
    fun joinWithoutApprovalBecomesMember() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, requiresApproval = false)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        assertEquals(Role.MEMBER, room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun joinWithApprovalBecomesPending() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, requiresApproval = true)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        assertEquals(Role.PENDING, room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun joinRejectsAlreadyMember() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        val entry = room.build(owner, EntryType.JOIN, joinBody(inviteId)) // owner is already a member
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    @Test
    fun joinRejectsRevokedInvite() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(owner, EntryType.INVITE_REVOKE, inviteRevokeBody(inviteId)))
        val entry = room.build(member, EntryType.JOIN, joinBody(inviteId))
        assertEquals(RejectReason.InviteRevoked, room.applyAndExpectReject(entry))
    }

    @Test
    fun joinRejectsExpiredInvite() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, expiresAt = 1_700_000_600L)))
        val entry = room.build(member, EntryType.JOIN, joinBody(inviteId))
        assertEquals(RejectReason.InviteExpired, room.applyAndExpectReject(entry, rts = 1_700_000_700L))
    }

    @Test
    fun joinRejectsExhaustedInvite() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, maxUses = 1)))
        room.apply(room.build(actor(crypto), EntryType.JOIN, joinBody(inviteId)))
        val second = actor(crypto)
        val entry = room.build(second, EntryType.JOIN, joinBody(inviteId))
        assertEquals(RejectReason.InviteExhausted, room.applyAndExpectReject(entry))
    }

    @Test
    fun joinRejectsUnknownInvite() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val entry = room.build(member, EntryType.JOIN, joinBody(crypto.randomBytes(16)))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    // ---- row 4/5: approve/reject ----

    @Test
    fun approveByAdminMakesPendingAMember() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, requiresApproval = true)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.APPROVE, approveBody(member.identity.userKey)))
        assertEquals(Role.MEMBER, room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun approveRejectsNonAdminAuthor() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val pendingA = actor(crypto)
        val pendingB = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, requiresApproval = true)))
        room.apply(room.build(pendingA, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(pendingB, EntryType.JOIN, joinBody(inviteId)))
        val entry = room.build(pendingA, EntryType.APPROVE, approveBody(pendingB.identity.userKey))
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(entry))
    }

    @Test
    fun approveRejectsTargetNotPending() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val entry = room.build(owner, EntryType.APPROVE, approveBody(owner.identity.userKey))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    @Test
    fun rejectByAdminRemovesPending() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, requiresApproval = true)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.REJECT, rejectBody(member.identity.userKey)))
        assertNull(room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun rejectRejectsTargetNotPending() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId))) // not pending, requiresApproval=false
        val entry = room.build(owner, EntryType.REJECT, rejectBody(member.identity.userKey))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    // ---- row 6: remove ----

    @Test
    fun ownerCanRemoveAnAdmin() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val admin = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(admin, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin")))
        room.apply(room.build(owner, EntryType.REMOVE, removeBody(admin.identity.userKey)))
        assertNull(room.state.roleOf(admin.identity.userKey))
    }

    @Test
    fun ownerCannotRemoveSelf() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val entry = room.build(owner, EntryType.REMOVE, removeBody(owner.identity.userKey))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    @Test
    fun adminCanRemoveMember() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val admin = actor(crypto)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(admin, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin")))
        room.apply(room.build(admin, EntryType.REMOVE, removeBody(member.identity.userKey)))
        assertNull(room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun adminCannotRemoveAnotherAdminOrOwner() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val adminA = actor(crypto)
        val adminB = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(adminA, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(adminB, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(adminA.identity.userKey, "admin")))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(adminB.identity.userKey, "admin")))
        val removeAdmin = room.build(adminA, EntryType.REMOVE, removeBody(adminB.identity.userKey))
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(removeAdmin))
        val removeOwner = room.build(adminA, EntryType.REMOVE, removeBody(owner.identity.userKey))
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(removeOwner))
    }

    @Test
    fun removeRejectsNonMemberTarget() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val stranger = actor(crypto)
        val entry = room.build(owner, EntryType.REMOVE, removeBody(stranger.identity.userKey))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    // ---- §3.4 / ADR-0012: rotationPending ----

    @Test
    fun removeSetsRotationPendingClearedOnlyByEpochRotate() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        assertEquals(false, room.state.rotationPending)

        room.apply(room.build(owner, EntryType.REMOVE, removeBody(member.identity.userKey)))
        assertEquals(true, room.state.rotationPending)

        // Unrelated entries don't clear it while a rotation is owed.
        room.apply(room.build(owner, EntryType.ROOM_SETTINGS, roomSettingsBody()))
        assertEquals(true, room.state.rotationPending)

        room.apply(room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey))))
        assertEquals(false, room.state.rotationPending)
    }

    @Test
    fun epochRotateByAnyAdminClearsRotationPendingEvenIfNotTheRemover() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val admin = actor(crypto)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(admin, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin")))
        room.apply(room.build(owner, EntryType.REMOVE, removeBody(member.identity.userKey))) // owner removes
        assertEquals(true, room.state.rotationPending)
        // A different admin (not the one who removed) rotates - still clears it.
        room.apply(room.build(admin, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, admin.identity.userKey))))
        assertEquals(false, room.state.rotationPending)
    }

    // ---- row 7: leave ----

    @Test
    fun memberCanLeave() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(member, EntryType.LEAVE, leaveBody()))
        assertNull(room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun ownerCannotLeaveWithoutTransferring() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val entry = room.build(owner, EntryType.LEAVE, leaveBody())
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    @Test
    fun leaveRejectsNonMemberAuthor() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val stranger = actor(crypto)
        val entry = room.build(stranger, EntryType.LEAVE, leaveBody())
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(entry))
    }

    // ---- row 8: setRole ----

    @Test
    fun ownerCanSetRoleToAdminAndBackToMember() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(member.identity.userKey, "admin")))
        assertEquals(Role.ADMIN, room.state.roleOf(member.identity.userKey))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(member.identity.userKey, "member")))
        assertEquals(Role.MEMBER, room.state.roleOf(member.identity.userKey))
    }

    @Test
    fun setRoleRejectsNonOwnerAuthor() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val admin = actor(crypto)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(admin, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin")))
        val entry = room.build(admin, EntryType.SET_ROLE, setRoleBody(member.identity.userKey, "admin"))
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(entry))
    }

    @Test
    fun setRoleRejectsTargetOwnerOrPendingOrInvalidRoleName() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val pending = actor(crypto)
        val member = actor(crypto)
        val inviteApproval = crypto.randomBytes(16)
        val inviteOpen = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteApproval, requiresApproval = true)))
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteOpen)))
        room.apply(room.build(pending, EntryType.JOIN, joinBody(inviteApproval)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteOpen)))

        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(room.build(owner, EntryType.SET_ROLE, setRoleBody(owner.identity.userKey, "admin"))))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(room.build(owner, EntryType.SET_ROLE, setRoleBody(pending.identity.userKey, "admin"))))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(room.build(owner, EntryType.SET_ROLE, setRoleBody(member.identity.userKey, "owner"))))
    }

    // ---- row 9: transferOwner ----

    @Test
    fun ownerCanTransferToAnAdmin() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val admin = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(admin, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin")))
        room.apply(room.build(owner, EntryType.TRANSFER_OWNER, transferOwnerBody(admin.identity.userKey)))
        assertEquals(Role.OWNER, room.state.roleOf(admin.identity.userKey))
        assertEquals(Role.ADMIN, room.state.roleOf(owner.identity.userKey))
    }

    @Test
    fun transferOwnerRejectsNonOwnerAuthorAndNonAdminTarget() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))

        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(room.build(member, EntryType.TRANSFER_OWNER, transferOwnerBody(member.identity.userKey))))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(room.build(owner, EntryType.TRANSFER_OWNER, transferOwnerBody(member.identity.userKey))))
    }

    // ---- row 10: epochRotate ----

    @Test
    fun epochRotateByOwnerCoveringExactMembersAccepted() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        room.apply(room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, member.identity.userKey))))
        assertEquals(1L, room.state.epoch)
    }

    @Test
    fun epochRotateExcludesPendingMembers() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val pending = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, requiresApproval = true)))
        room.apply(room.build(pending, EntryType.JOIN, joinBody(inviteId)))
        // Including the pending user must fail...
        val withPending = room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, pending.identity.userKey)))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(withPending))
        // ...only the non-pending owner must succeed.
        room.apply(room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey))))
        assertEquals(1L, room.state.epoch)
    }

    @Test
    fun epochRotateRejectsNonAdminAuthor() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        val entry = room.build(member, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, member.identity.userKey)))
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(entry))
    }

    @Test
    fun epochRotateRejectsIncompleteMemberSet() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        val entry = room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey))) // missing member
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    @Test
    fun epochRotateRejectsDuplicateUserInList() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val entry = room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, owner.identity.userKey)))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    @Test
    fun epochRotateRejectsNonSequentialEpoch() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val entry = room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(5, listOf(owner.identity.userKey)))
        assertIs<RejectReason.Invalid>(room.applyAndExpectReject(entry))
    }

    // ---- row 11: roomSettings ----

    @Test
    fun roomSettingsByAdminAccepted() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val before = room.state.nextIndex
        room.apply(room.build(owner, EntryType.ROOM_SETTINGS, roomSettingsBody()))
        assertEquals(before + 1, room.state.nextIndex)
    }

    @Test
    fun roomSettingsRejectsNonAdminAuthor() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        room.apply(room.build(member, EntryType.JOIN, joinBody(inviteId)))
        val entry = room.build(member, EntryType.ROOM_SETTINGS, roomSettingsBody())
        assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(entry))
    }

    // ---- chain-level reject, not type-specific ----

    @Test
    fun rejectsStaleHead() = runTest {
        val crypto = crypto(); val owner = actor(crypto)
        val room = freshRoom(crypto, owner)
        val member = actor(crypto)
        val inviteId = crypto.randomBytes(16)
        val staleHead = room.head
        val staleIndex = room.index
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
        // Built against the now-stale head/index - as if two clients raced on the same prev.
        val stale = LogEntry.sign(crypto, member.deviceKey.secretKey, room.roomId, staleIndex, staleHead, member.identity.userKey, member.cert, EntryType.JOIN, joinBody(inviteId), 1L)
        assertEquals(RejectReason.BadChain, room.applyAndExpectReject(stale))
    }

    // ---- full room lifecycle ----

    @Test
    fun fullRoomLifecycle() = runTest {
        val crypto = crypto()
        val owner = actor(crypto)
        val room = freshRoom(crypto, owner)

        val userA = actor(crypto)
        val approvalInvite = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(approvalInvite, requiresApproval = true)))
        room.apply(room.build(userA, EntryType.JOIN, joinBody(approvalInvite)))
        assertEquals(Role.PENDING, room.state.roleOf(userA.identity.userKey))
        room.apply(room.build(owner, EntryType.APPROVE, approveBody(userA.identity.userKey)))
        assertEquals(Role.MEMBER, room.state.roleOf(userA.identity.userKey))
        room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(userA.identity.userKey, "admin")))
        assertEquals(Role.ADMIN, room.state.roleOf(userA.identity.userKey))

        val userB = actor(crypto)
        val userC = actor(crypto)
        val openInvite = crypto.randomBytes(16)
        room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(openInvite, requiresApproval = false)))
        room.apply(room.build(userB, EntryType.JOIN, joinBody(openInvite)))
        room.apply(room.build(userC, EntryType.JOIN, joinBody(openInvite)))

        room.apply(room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, userA.identity.userKey, userB.identity.userKey, userC.identity.userKey))))
        assertEquals(1L, room.state.epoch)

        room.apply(room.build(userA, EntryType.REMOVE, removeBody(userB.identity.userKey)))
        assertNull(room.state.roleOf(userB.identity.userKey))

        room.apply(room.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(2, listOf(owner.identity.userKey, userA.identity.userKey, userC.identity.userKey))))
        assertEquals(2L, room.state.epoch)

        room.apply(room.build(userC, EntryType.LEAVE, leaveBody()))
        assertNull(room.state.roleOf(userC.identity.userKey))

        room.apply(room.build(owner, EntryType.TRANSFER_OWNER, transferOwnerBody(userA.identity.userKey)))
        assertEquals(Role.OWNER, room.state.roleOf(userA.identity.userKey))
        assertEquals(Role.ADMIN, room.state.roleOf(owner.identity.userKey))
        assertEquals(2L, room.state.epoch)
    }

    // ---- property test ----

    @Test
    fun propertyRandomMemberSetsStayConsistentAndRejectsOneBadMutation() = runTest {
        checkAll(Arb.int(2..5)) { memberCount ->
            val crypto = crypto()
            val owner = actor(crypto)
            val room = freshRoom(crypto, owner)
            val members = (1..memberCount).map { actor(crypto) }
            val inviteId = crypto.randomBytes(16)
            room.apply(room.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId, requiresApproval = false)))
            for (m in members) room.apply(room.build(m, EntryType.JOIN, joinBody(inviteId)))

            members.forEach { assertEquals(Role.MEMBER, room.state.roleOf(it.identity.userKey)) }
            assertEquals(Role.OWNER, room.state.roleOf(owner.identity.userKey))

            // deliberately broken: a plain member may never remove the owner
            val attacker = members[0]
            val badEntry = room.build(attacker, EntryType.REMOVE, removeBody(owner.identity.userKey))
            assertEquals(RejectReason.Unauthorized, room.applyAndExpectReject(badEntry))

            // valid continuation: promote one member, have them remove another
            val admin = members[0]
            room.apply(room.build(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin")))
            val victim = members[1]
            room.apply(room.build(admin, EntryType.REMOVE, removeBody(victim.identity.userKey)))
            assertNull(room.state.roleOf(victim.identity.userKey))

            // invariant across the whole run: exactly one owner
            assertEquals(Role.OWNER, room.state.roleOf(owner.identity.userKey))
        }
    }
}
