package org.squaddle.core.membership

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.encoding.Hex

/**
 * Pure state machine for PROTOCOL.md §3.3. Every `apply()` returns a brand new
 * [MembershipStateImpl] (or a [RejectReason]) - nothing is mutated in place, so a caller can keep
 * a reference to an old state (e.g. to answer "was `rts` before this epoch rotate?") safely.
 *
 * Two authorization rules go slightly beyond the literal §3.3 table text, both documented inline
 * where they apply: `epochRotate` must bump `epoch` by exactly 1 (the table only says the member
 * set must be exact, but an epoch number that could be skipped or repeated would leave the content
 * plane unable to tell which epoch key to use), and `inviteCreate` rejects a duplicate `inviteId`
 * (re-using one would silently clobber the existing invite's `uses`/`revoked` state).
 */
public class MembershipStateImpl private constructor(
    private val crypto: Crypto,
    override val roomId: ByteArray,
    override val headHash: ByteArray,
    override val nextIndex: Long,
    override val epoch: Long,
    private val roles: Map<String, Role>,
    private val invitesById: Map<String, Invite>,
    override val rotationPending: Boolean,
    override val membersCanCreateEvents: Boolean,
) : MembershipState {

    public companion object {
        /** No room exists yet - the only entry `apply()` will accept from here is a genesis. */
        public fun empty(crypto: Crypto): MembershipState =
            MembershipStateImpl(crypto, ByteArray(32), ByteArray(32), 0L, 0L, emptyMap(), emptyMap(), rotationPending = false, membersCanCreateEvents = true)
    }

    override fun roleOf(user: ByteArray): Role? = roles[user.hex()]
    override fun invites(): Collection<Invite> = invitesById.values
    override fun members(): Collection<Member> = roles.map { (hex, role) -> Member(hex.unhex(), role) }

    override fun apply(stored: StoredEntry): Result<MembershipState> {
        val entry = stored.entry
        if (!entry.verify(crypto)) return reject(RejectReason.BadSignature)
        if (entry.index != nextIndex) return reject(RejectReason.BadChain)

        if (nextIndex == 0L) return applyGenesis(entry)

        if (!entry.room.contentEquals(roomId)) return reject(RejectReason.Invalid("room id mismatch"))
        if (entry.prev == null || !entry.prev.contentEquals(headHash)) return reject(RejectReason.BadChain)

        val authorRole = roles[entry.author.hex()]
        return when (entry.type) {
            EntryType.GENESIS -> reject(RejectReason.Invalid("genesis only valid at index 0"))
            EntryType.INVITE_CREATE -> applyInviteCreate(entry, authorRole)
            EntryType.INVITE_REVOKE -> applyInviteRevoke(entry, authorRole)
            EntryType.JOIN -> applyJoin(entry, stored.rts)
            EntryType.APPROVE -> applyApproveOrReject(entry, authorRole, approve = true)
            EntryType.REJECT -> applyApproveOrReject(entry, authorRole, approve = false)
            EntryType.REMOVE -> applyRemove(entry, authorRole)
            EntryType.LEAVE -> applyLeave(entry, authorRole)
            EntryType.SET_ROLE -> applySetRole(entry, authorRole)
            EntryType.TRANSFER_OWNER -> applyTransferOwner(entry, authorRole)
            EntryType.EPOCH_ROTATE -> applyEpochRotate(entry, authorRole)
            EntryType.ROOM_SETTINGS -> applyRoomSettings(entry, authorRole)
        }
    }

    // ---- §3.3 row 0 ----

    private fun applyGenesis(entry: LogEntry): Result<MembershipState> {
        if (entry.type != EntryType.GENESIS) return reject(RejectReason.Invalid("first entry must be genesis"))
        if (entry.prev != null) return reject(RejectReason.BadChain)
        val nonce = entry.body.entries.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("genesis missing roomNonce"))
        val expectedRoomId = roomId(crypto, entry.author, nonce)
        if (!expectedRoomId.contentEquals(entry.room)) return reject(RejectReason.Invalid("roomId does not match author+nonce"))
        return next(entry, roles = mapOf(entry.author.hex() to Role.OWNER))
    }

    // ---- §3.3 row 1/2: invites ----

    private fun applyInviteCreate(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        if (authorRole != Role.OWNER && authorRole != Role.ADMIN) return reject(RejectReason.Unauthorized)
        val body = entry.body.entries
        val inviteId = body.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("inviteCreate missing inviteId"))
        val idHex = inviteId.hex()
        if (invitesById.containsKey(idHex)) return reject(RejectReason.Invalid("invite id already exists"))
        val requiresApproval = body.boolOrNull(3L) ?: return reject(RejectReason.Invalid("inviteCreate missing requiresApproval"))
        val role = body.textOrNull(4L) ?: return reject(RejectReason.Invalid("inviteCreate missing role"))
        if (role != "member") return reject(RejectReason.Invalid("inviteCreate role must be \"member\", was '$role'"))
        val invite = Invite(
            id = inviteId,
            expiresAt = body.uintOrNull(1L),
            maxUses = body.uintOrNull(2L)?.toInt(),
            requiresApproval = requiresApproval,
        )
        return next(entry, invites = invitesById + (idHex to invite))
    }

    private fun applyInviteRevoke(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        if (authorRole != Role.OWNER && authorRole != Role.ADMIN) return reject(RejectReason.Unauthorized)
        val inviteId = entry.body.entries.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("inviteRevoke missing inviteId"))
        val idHex = inviteId.hex()
        val invite = invitesById[idHex] ?: return reject(RejectReason.Invalid("invite not found"))
        return next(entry, invites = invitesById + (idHex to invite.copy(revoked = true)))
    }

    // ---- §3.3 row 3: join ----

    private fun applyJoin(entry: LogEntry, rts: Long): Result<MembershipState> {
        val authorHex = entry.author.hex()
        if (roles.containsKey(authorHex)) return reject(RejectReason.Invalid("already a member"))
        val inviteId = entry.body.entries.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("join missing inviteId"))
        val idHex = inviteId.hex()
        val invite = invitesById[idHex] ?: return reject(RejectReason.Invalid("invite not found"))
        if (invite.revoked) return reject(RejectReason.InviteRevoked)
        if (invite.expiresAt != null && rts >= invite.expiresAt) return reject(RejectReason.InviteExpired)
        if (invite.maxUses != null && invite.uses >= invite.maxUses) return reject(RejectReason.InviteExhausted)
        val newRole = if (invite.requiresApproval) Role.PENDING else Role.MEMBER
        return next(
            entry,
            roles = roles + (authorHex to newRole),
            invites = invitesById + (idHex to invite.copy(uses = invite.uses + 1)),
        )
    }

    // ---- §3.3 row 4/5: approve/reject ----

    private fun applyApproveOrReject(entry: LogEntry, authorRole: Role?, approve: Boolean): Result<MembershipState> {
        if (authorRole != Role.OWNER && authorRole != Role.ADMIN) return reject(RejectReason.Unauthorized)
        val body = entry.body.entries
        val target = body.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("missing target user"))
        val targetHex = target.hex()
        if (roles[targetHex] != Role.PENDING) return reject(RejectReason.Invalid("target is not pending"))
        if (approve) {
            if (body.bytesOrNull(1L) == null) return reject(RejectReason.Invalid("approve missing wrappedEpochKey"))
            return next(entry, roles = roles + (targetHex to Role.MEMBER))
        }
        return next(entry, roles = roles - targetHex)
    }

    // ---- §3.3 row 6: remove ----

    private fun applyRemove(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        val target = entry.body.entries.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("remove missing target user"))
        val targetHex = target.hex()
        val targetRole = roles[targetHex] ?: return reject(RejectReason.Invalid("target is not a member"))
        when (authorRole) {
            Role.OWNER -> if (target.contentEquals(entry.author)) return reject(RejectReason.Invalid("owner cannot remove self"))
            Role.ADMIN -> if (targetRole != Role.MEMBER) return reject(RejectReason.Unauthorized)
            else -> return reject(RejectReason.Unauthorized)
        }
        return next(entry, roles = roles - targetHex, rotationPending = true)
    }

    // ---- §3.3 row 7: leave ----

    private fun applyLeave(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        when (authorRole) {
            Role.MEMBER, Role.ADMIN -> {}
            Role.OWNER -> return reject(RejectReason.Invalid("owner must transferOwner before leaving"))
            else -> return reject(RejectReason.Unauthorized)
        }
        return next(entry, roles = roles - entry.author.hex())
    }

    // ---- §3.3 row 8: setRole ----

    private fun applySetRole(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        if (authorRole != Role.OWNER) return reject(RejectReason.Unauthorized)
        val body = entry.body.entries
        val target = body.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("setRole missing target user"))
        val targetHex = target.hex()
        val roleText = body.textOrNull(1L) ?: return reject(RejectReason.Invalid("setRole missing role"))
        val newRole = when (roleText) {
            "admin" -> Role.ADMIN
            "member" -> Role.MEMBER
            else -> return reject(RejectReason.Invalid("role must be admin or member, was '$roleText'"))
        }
        when (roles[targetHex]) {
            null -> return reject(RejectReason.Invalid("target is not a member"))
            Role.PENDING -> return reject(RejectReason.Invalid("target is pending, approve or reject first"))
            Role.OWNER -> return reject(RejectReason.Invalid("target is the owner, use transferOwner"))
            else -> {}
        }
        return next(entry, roles = roles + (targetHex to newRole))
    }

    // ---- §3.3 row 9: transferOwner ----

    private fun applyTransferOwner(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        if (authorRole != Role.OWNER) return reject(RejectReason.Unauthorized)
        val target = entry.body.entries.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("transferOwner missing target user"))
        val targetHex = target.hex()
        if (roles[targetHex] != Role.ADMIN) return reject(RejectReason.Invalid("transferOwner target must currently be admin"))
        return next(entry, roles = roles + (entry.author.hex() to Role.ADMIN) + (targetHex to Role.OWNER))
    }

    // ---- §3.3 row 10: epochRotate ----

    private fun applyEpochRotate(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        if (authorRole != Role.OWNER && authorRole != Role.ADMIN) return reject(RejectReason.Unauthorized)
        val body = entry.body.entries
        val newEpoch = body.uintOrNull(0L) ?: return reject(RejectReason.Invalid("epochRotate missing epoch"))
        if (newEpoch != epoch + 1) return reject(RejectReason.Invalid("epoch must increase by exactly 1, was $epoch -> $newEpoch"))
        val wrapped = body.arrayOrNull(1L) ?: return reject(RejectReason.Invalid("epochRotate missing wrapped key list"))
        val listedUsers = mutableListOf<String>()
        for (item in wrapped) {
            val itemMap = (item as? CborValue.Map)?.entries ?: return reject(RejectReason.Invalid("epochRotate entry is not a map"))
            val user = itemMap.bytesOrNull(0L) ?: return reject(RejectReason.Invalid("epochRotate entry missing user"))
            if (itemMap.bytesOrNull(1L) == null) return reject(RejectReason.Invalid("epochRotate entry missing sealedKey"))
            listedUsers += user.hex()
        }
        if (listedUsers.size != listedUsers.toSet().size) return reject(RejectReason.Invalid("epochRotate lists the same user more than once"))
        val currentNonPending = roles.filterValues { it != Role.PENDING }.keys
        if (listedUsers.toSet() != currentNonPending) return reject(RejectReason.Invalid("epochRotate must contain exactly the current non-pending members"))
        return next(entry, epoch = newEpoch, rotationPending = false)
    }

    // ---- §3.3 row 11: roomSettings ----

    private fun applyRoomSettings(entry: LogEntry, authorRole: Role?): Result<MembershipState> {
        if (authorRole != Role.OWNER && authorRole != Role.ADMIN) return reject(RejectReason.Unauthorized)
        val body = entry.body.entries
        val membersCanCreateEvents = if (body.containsKey(1L)) {
            body.boolOrNull(1L) ?: return reject(RejectReason.Invalid("roomSettings membersCanCreateEvents must be a bool"))
        } else {
            this.membersCanCreateEvents
        }
        return next(entry, membersCanCreateEvents = membersCanCreateEvents)
    }

    // ---- plumbing ----

    private fun next(
        entry: LogEntry,
        roles: Map<String, Role> = this.roles,
        invites: Map<String, Invite> = this.invitesById,
        epoch: Long = this.epoch,
        rotationPending: Boolean = this.rotationPending,
        membersCanCreateEvents: Boolean = this.membersCanCreateEvents,
    ): Result<MembershipState> = Result.success(
        MembershipStateImpl(crypto, entry.room, entry.entryHash(crypto), entry.index + 1, epoch, roles, invites, rotationPending, membersCanCreateEvents),
    )

    private fun reject(reason: RejectReason): Result<MembershipState> = Result.failure(MembershipRejectException(reason))
}

private fun ByteArray.hex(): String = Hex.encode(this)

private fun String.unhex(): ByteArray = Hex.decode(this)

private fun Map<Long, CborValue>.bytesOrNull(key: Long): ByteArray? = (this[key] as? CborValue.Bytes)?.value
private fun Map<Long, CborValue>.uintOrNull(key: Long): Long? = (this[key] as? CborValue.UInt)?.value
private fun Map<Long, CborValue>.textOrNull(key: Long): String? = (this[key] as? CborValue.Text)?.value
private fun Map<Long, CborValue>.boolOrNull(key: Long): Boolean? = (this[key] as? CborValue.Bool)?.value
private fun Map<Long, CborValue>.arrayOrNull(key: Long): List<CborValue>? = (this[key] as? CborValue.Array)?.items
