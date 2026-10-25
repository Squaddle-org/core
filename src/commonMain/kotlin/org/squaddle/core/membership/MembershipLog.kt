package org.squaddle.core.membership

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert

/** PROTOCOL.md §3. */
public enum class Role { OWNER, ADMIN, MEMBER, PENDING }

public enum class EntryType(public val code: Int) {
    GENESIS(0), INVITE_CREATE(1), INVITE_REVOKE(2), JOIN(3), APPROVE(4), REJECT(5),
    REMOVE(6), LEAVE(7), SET_ROLE(8), TRANSFER_OWNER(9), EPOCH_ROTATE(10), ROOM_SETTINGS(11),
}

/** PROTOCOL.md §3.2. `body` is already a [CborValue.Map] - every §3.3 body is a small int-keyed map. */
public data class LogEntry(
    val v: Int = 1,
    val room: ByteArray,
    val index: Long,
    val prev: ByteArray?,
    val author: ByteArray,
    val cert: DeviceCert,
    val type: EntryType,
    val body: CborValue.Map,
    val ts: Long,
    val sig: ByteArray? = null,
) {
    public companion object {
        public const val DOMAIN: String = "logentry"

        /** Decodes a full (0..9, incl. [sig]) CBOR-encoded LogEntry as received from the wire
         * (`GET /rooms/{room}/log`). `null` on malformed CBOR or a field-shape mismatch - never
         * throws; does NOT verify the signature/cert, call [verify] for that. Mirrors relay's own
         * `DecodeLogEntry`. */
        public fun decode(bytes: ByteArray): LogEntry? {
            val map = try {
                (CanonicalCborCodec.decode(bytes) as? CborValue.Map)?.entries ?: return null
            } catch (e: org.squaddle.core.encoding.CborFormatException) {
                return null
            }
            return try {
                val certBytes = CanonicalCborCodec.encode(map.getValue(5L))
                val cert = DeviceCert.decode(certBytes) ?: return null
                val typeCode = (map.getValue(6L) as CborValue.UInt).value.toInt()
                val type = EntryType.entries.firstOrNull { it.code == typeCode } ?: return null
                LogEntry(
                    v = (map.getValue(0L) as CborValue.UInt).value.toInt(),
                    room = (map.getValue(1L) as CborValue.Bytes).value,
                    index = (map.getValue(2L) as CborValue.UInt).value,
                    prev = (map[3L] as? CborValue.Bytes)?.value,
                    author = (map.getValue(4L) as CborValue.Bytes).value,
                    cert = cert,
                    type = type,
                    body = map.getValue(7L) as CborValue.Map,
                    ts = (map.getValue(8L) as CborValue.UInt).value,
                    sig = (map[9L] as? CborValue.Bytes)?.value,
                )
            } catch (e: NoSuchElementException) {
                null
            } catch (e: ClassCastException) {
                null
            }
        }

        /** Builds and signs a v1 LogEntry with [deviceSecretKey] (the author device's Ed25519 key). */
        public fun sign(
            crypto: Crypto,
            deviceSecretKey: ByteArray,
            room: ByteArray,
            index: Long,
            prev: ByteArray?,
            author: ByteArray,
            cert: DeviceCert,
            type: EntryType,
            body: CborValue.Map,
            ts: Long,
        ): LogEntry {
            val unsigned = LogEntry(
                v = 1, room = room, index = index, prev = prev, author = author,
                cert = cert, type = type, body = body, ts = ts,
            )
            val sig = crypto.sign(deviceSecretKey, crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
            return unsigned.copy(sig = sig)
        }
    }

    /** Fields 0..8, i.e. the struct without [sig] - exactly what is signed over, PROTOCOL.md §1. */
    internal fun toUnsignedCbor(): CborValue {
        val entries = linkedMapOf<Long, CborValue>(
            0L to CborValue.UInt(v.toLong()),
            1L to CborValue.Bytes(room),
            2L to CborValue.UInt(index),
        )
        prev?.let { entries[3L] = CborValue.Bytes(it) }
        entries[4L] = CborValue.Bytes(author)
        entries[5L] = cert.toFullCbor()
        entries[6L] = CborValue.UInt(type.code.toLong())
        entries[7L] = body
        entries[8L] = CborValue.UInt(ts)
        return CborValue.Map(entries)
    }

    /** All fields 0..9 incl. [sig] - what `entryHash` is computed over and what travels on the wire. */
    internal fun toFullCbor(): CborValue {
        val entries = (toUnsignedCbor() as CborValue.Map).entries.toMutableMap()
        sig?.let { entries[9L] = CborValue.Bytes(it) }
        return CborValue.Map(entries)
    }

    /** `entryHash = BLAKE2b(CBOR(full entry incl. sig))` - PROTOCOL.md §3.2. A plain hash, not domain-separated. */
    public fun entryHash(crypto: Crypto): ByteArray = crypto.blake2b256(CanonicalCborCodec.encode(toFullCbor()))

    /**
     * Self-contained crypto/structural validity: unknown [v], [cert] not valid, [cert]'s claimed
     * user doesn't match [author], or [sig] doesn't verify under [cert]'s device key - the device
     * named in the attached cert signs the entry, not the user key (PROTOCOL.md §3.2 field 9).
     * Chain and authorization rules (index/prev/room match, §3.3 row) are [MembershipState]'s job -
     * they need sequence context this single entry doesn't have.
     */
    public fun verify(crypto: Crypto): Boolean {
        val signature = sig ?: return false
        if (v != 1) return false
        if (!cert.verify(crypto)) return false
        if (!cert.user.contentEquals(author)) return false
        val signingInput = crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(toUnsignedCbor()))
        return crypto.verify(cert.device, signingInput, signature)
    }
}

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

/** Carries *which* §3.3 row an `apply()` failed, as the payload of the `Result.failure`. */
public class MembershipRejectException(public val reason: RejectReason) : Exception(reason.toString())

/** One (user, role) pair - for callers that need to enumerate the whole room rather than look up
 * a single user via [MembershipState.roleOf] (e.g. building an `epochRotate`'s per-user wrap
 * list, §3.3 row 10: "MUST contain exactly the current non-pending members"). Mirrors relay's own
 * `membership.Member`/`State.Members()` in `relay/internal/membership/state.go`. */
public data class Member(public val user: ByteArray, public val role: Role)

/** Immutable - a new [MembershipState] gets a new `Invite` (e.g. `copy(uses = uses + 1)`), never
 * a mutated shared one, so two state snapshots can never alias each other's invite records. */
public data class Invite(
    val id: ByteArray,
    val expiresAt: Long?,
    val maxUses: Int?,
    val requiresApproval: Boolean,
    val uses: Int = 0,
    val revoked: Boolean = false,
)

/** Pure state machine. Identical rules MUST be implemented in relay/internal/membership. */
public interface MembershipState {
    public val roomId: ByteArray
    public val headHash: ByteArray
    public val nextIndex: Long
    public val epoch: Long

    /** PROTOCOL.md §3.4 / ADR-0012: true from an accepted `remove` until the next accepted
     * `epochRotate`. While true, content-plane ops MUST be rejected (`rotation_required`) -
     * membership-log appends other than `epochRotate` are unaffected. */
    public val rotationPending: Boolean
    public fun roleOf(user: ByteArray): Role?
    public fun invites(): Collection<Invite>

    /** Every current (user, role) pair, incl. pending. */
    public fun members(): Collection<Member>

    /** Returns the new state or the reason the entry must be rejected. */
    public fun apply(stored: StoredEntry): Result<MembershipState>
}
