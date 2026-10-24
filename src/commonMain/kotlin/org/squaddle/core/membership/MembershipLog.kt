package org.squaddle.core.membership

import org.squaddle.core.identity.DeviceCert

/** PROTOCOL.md §3. */
public enum class Role { OWNER, ADMIN, MEMBER, PENDING }

public enum class EntryType(public val code: Int) {
    GENESIS(0), INVITE_CREATE(1), INVITE_REVOKE(2), JOIN(3), APPROVE(4), REJECT(5),
    REMOVE(6), LEAVE(7), SET_ROLE(8), TRANSFER_OWNER(9), EPOCH_ROTATE(10), ROOM_SETTINGS(11),
}

public data class LogEntry(
    val v: Int = 1,
    val room: ByteArray,
    val index: Long,
    val prev: ByteArray?,
    val author: ByteArray,
    val cert: DeviceCert,
    val type: EntryType,
    val body: Map<Long, Any?>,
    val ts: Long,
    val sig: ByteArray?,
)

/** Relay-assigned timestamp travels next to the entry, never inside the signed part. */
public data class StoredEntry(val entry: LogEntry, val rts: Long)

public sealed interface RejectReason {
    public data object BadSignature : RejectReason
    public data object BadChain : RejectReason
    public data object Unauthorized : RejectReason
    public data object InviteExpired : RejectReason
    public data object InviteExhausted : RejectReason
    public data object InviteRevoked : RejectReason
    public data class Invalid(val why: String) : RejectReason
}

public data class Invite(
    val id: ByteArray,
    val expiresAt: Long?,
    val maxUses: Int?,
    val requiresApproval: Boolean,
    var uses: Int = 0,
    var revoked: Boolean = false,
)

/** Pure state machine. Identical rules MUST be implemented in relay/internal/membership. */
public interface MembershipState {
    public val roomId: ByteArray
    public val headHash: ByteArray
    public val nextIndex: Long
    public val epoch: Long
    public fun roleOf(user: ByteArray): Role?
    public fun invites(): Collection<Invite>

    /** Returns the new state or the reason the entry must be rejected. */
    public fun apply(stored: StoredEntry): Result<MembershipState>
}
// TODO(M1): implementation + exhaustive reject tests (one per row in PROTOCOL.md §3.3)
