package org.squaddle.core.ops

import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.MembershipState
import org.squaddle.core.membership.Role
import org.squaddle.core.membership.StoredEntry

/** Hashable form of a ByteArray key - raw `ByteArray` has reference equality/hashCode, which
 * breaks `Map`/`Set` usage (the same gotcha `LwwStamp`'s `compareTo` already works around). */
private fun ByteArray.toKey(): String = joinToString("") { "%02x".format(it) }

private fun Role?.isActiveMember(): Boolean = this != null && this != Role.PENDING
private fun Role?.isAdminOrOwner(): Boolean = this == Role.ADMIN || this == Role.OWNER

private fun Idea.withField(field: String, value: Any?, stamp: LwwStamp): Idea = when (field) {
    "title" -> if (stamp > titleStamp) copy(title = value as? String ?: title, titleStamp = stamp) else this
    "desc" -> if (stamp > descStamp) copy(desc = value as? String, descStamp = stamp) else this
    "tags" -> if (stamp > tagsStamp) copy(tags = (value as? List<*>)?.map { it.toString() } ?: emptyList(), tagsStamp = stamp) else this
    "status" -> if (stamp > statusStamp) copy(status = value as? String, statusStamp = stamp) else this
    else -> this // unknown field name: ignore, same forward-compat spirit as unknown op types
}

/** `deleted` is its own independent LWW-tracked field - once a delete's stamp wins, nothing ever
 * writes `false` back (no `idea.undelete` type exists), which is exactly what makes a tombstone
 * "win" permanently: it's not a special case, just the natural result of there being no
 * competing write. */
private fun Idea.withDelete(stamp: LwwStamp): Idea = if (stamp > deletedStamp) copy(deleted = true, deletedStamp = stamp) else this

private fun Event.withField(field: String, value: Any?, stamp: LwwStamp): Event = when (field) {
    "title" -> if (stamp > titleStamp) copy(title = value as? String ?: title, titleStamp = stamp) else this
    "start" -> if (stamp > startStamp) copy(start = (value as? Long) ?: start, startStamp = stamp) else this
    "end" -> if (stamp > endStamp) copy(end = value as? Long, endStamp = stamp) else this
    "tz" -> if (stamp > tzStamp) copy(tz = value as? String ?: tz, tzStamp = stamp) else this
    "location" -> if (stamp > locationStamp) copy(location = value as? String, locationStamp = stamp) else this
    "allDay" -> if (stamp > allDayStamp) copy(allDay = (value as? Boolean) ?: allDay, allDayStamp = stamp) else this
    else -> this
}

/**
 * Per-epoch membership snapshots, built once by replaying a room's accepted [StoredEntry]
 * sequence - the only thing that lets op authorization be evaluated against "the MembershipState
 * at the op's epoch" rather than whatever the CURRENT roster happens to be (an op's author may
 * since have been removed, promoted, demoted, etc. - that must not retroactively invalidate or
 * reinterpret an op that was legitimately authorized when it was created). A snapshot is taken at
 * epoch 0 (right after genesis) and right after every accepted `epochRotate` - i.e. "the roster as
 * of the *start* of that epoch", not tracking finer-grained role changes that happen later within
 * the same epoch (the relay never links an op to a precise log position, only to an epoch number,
 * so this is the finest granularity the data actually supports).
 */
public class MembershipHistory private constructor(
    private val snapshots: Map<Long, MembershipState>,
    public val current: MembershipState,
) {
    /** `null` if [epoch] predates every known snapshot (e.g. a malformed/adversarial op epoch) -
     * never throws. Falls back to the nearest lower epoch if [epoch] itself has no snapshot; in
     * practice this never happens for a well-behaved relay (PROTOCOL.md §3.4: ops are rejected
     * with `stale_epoch` unless their epoch is the room's current one at submission time, so every
     * epoch an accepted op ever carries is one this room has actually reached). */
    public fun roleAt(epoch: Long, user: ByteArray): Role? {
        val state = snapshots[epoch] ?: snapshots.keys.filter { it <= epoch }.maxOrNull()?.let { snapshots[it] }
        return state?.roleOf(user)
    }

    public companion object {
        public fun build(entries: List<StoredEntry>, empty: MembershipState): MembershipHistory {
            var state = empty
            val snapshots = mutableMapOf<Long, MembershipState>()
            for (stored in entries) {
                state = state.apply(stored).getOrThrow()
                if (stored.entry.index == 0L || stored.entry.type == EntryType.EPOCH_ROTATE) {
                    snapshots[state.epoch] = state
                }
            }
            return MembershipHistory(snapshots, state)
        }
    }
}

public data class Idea(
    val id: ByteArray,
    val createdBy: ByteArray,
    val title: String,
    val titleStamp: LwwStamp,
    val desc: String?,
    val descStamp: LwwStamp,
    val tags: List<String>,
    val tagsStamp: LwwStamp,
    val status: String?,
    val statusStamp: LwwStamp,
    val deleted: Boolean,
    val deletedStamp: LwwStamp,
)

public data class Comment(
    val id: ByteArray,
    val ideaId: ByteArray,
    val author: ByteArray,
    val text: String,
    val deleted: Boolean,
    val deletedStamp: LwwStamp,
)

public data class Event(
    val id: ByteArray,
    val createdBy: ByteArray,
    val ideaId: ByteArray?,
    val title: String,
    val titleStamp: LwwStamp,
    val start: Long,
    val startStamp: LwwStamp,
    val end: Long?,
    val endStamp: LwwStamp,
    val tz: String,
    val tzStamp: LwwStamp,
    val location: String?,
    val locationStamp: LwwStamp,
    val allDay: Boolean,
    val allDayStamp: LwwStamp,
    val cancelled: Boolean,
    val cancelledStamp: LwwStamp,
)

public data class Vote(val value: Int, val stamp: LwwStamp)
public data class Rsvp(val value: String, val stamp: LwwStamp)
public data class Profile(val displayName: String, val emoji: String?, val stamp: LwwStamp)

/**
 * The materialized content-plane view (PROTOCOL.md §4.2), folded from verified+decrypted ops.
 * Immutable; [fold] is a pure function over a collection with no order dependence - every field
 * converges to its max-[LwwStamp] write regardless of the order ops are supplied in, which is
 * exactly what makes the result order-independent (see `RoomStateTest`'s permutation property).
 *
 * `event.create`'s "admin, or member if room setting allows" (§4.2) is only implemented for its
 * fully-specified half (admin/owner) - the room-setting half needs a field number PROTOCOL.md's
 * §3.3 `roomSettings` body never gives (`{0:joinApprovalDefault?, …}` - the "…" covers fields the
 * spec never numbers). Needs a spec PR before a plain member can ever create events here.
 */
public data class RoomState(
    val ideas: Map<String, Idea> = emptyMap(),
    val comments: Map<String, Comment> = emptyMap(),
    val events: Map<String, Event> = emptyMap(),
    val votes: Map<String, Vote> = emptyMap(), // key: ideaIdHex + authorHex
    val rsvps: Map<String, Rsvp> = emptyMap(), // key: eventIdHex + authorHex
    val profiles: Map<String, Profile> = emptyMap(), // key: authorHex
) {
    public companion object {
        private val NEVER = LwwStamp(Long.MIN_VALUE, ByteArray(0))

        public fun fold(ops: List<Pair<OpEnvelope, OpBody>>, history: MembershipHistory): RoomState {
            var state = RoomState()
            for ((env, body) in ops) {
                val role = history.roleAt(env.epoch, env.author)
                if (!role.isActiveMember()) continue // baseline: every op type requires an active author
                val stamp = LwwStamp(env.lamport, env.device)

                state = when (body) {
                    is OpBody.IdeaCreate -> state.withIdeaCreate(env, body, stamp)
                    is OpBody.IdeaSet -> state.withIdeaField(env, body.id, role) { it.withField(body.field, body.value, stamp) }
                    is OpBody.IdeaDelete -> state.withIdeaField(env, body.id, role) { it.withDelete(stamp) }
                    is OpBody.VoteSet -> state.withVote(env, body, stamp)
                    is OpBody.CommentAdd -> state.withCommentAdd(env, body, stamp)
                    is OpBody.CommentDelete -> state.withCommentDelete(env, body, role, stamp)
                    is OpBody.EventCreate -> state.withEventCreate(env, body, role, stamp)
                    is OpBody.EventSet -> state.withEventField(env, body.id, role) { it.withField(body.field, body.value, stamp) }
                    is OpBody.EventCancel -> state.withEventCancel(env, body, role, stamp)
                    is OpBody.RsvpSet -> state.withRsvp(env, body, stamp)
                    is OpBody.ProfileSet -> state.withProfile(env, body, stamp)
                    is OpBody.Unknown -> state // §4.2: "Unknown types MUST be ignored"
                }
            }
            return state
        }
    }

    private fun withIdeaCreate(env: OpEnvelope, body: OpBody.IdeaCreate, stamp: LwwStamp): RoomState {
        val key = body.id.toKey()
        if (ideas.containsKey(key)) return this // a create is not a field write - first one wins, no LWW re-creation
        val idea = Idea(
            id = body.id, createdBy = env.author,
            title = body.title, titleStamp = stamp,
            desc = body.desc, descStamp = stamp,
            tags = body.tags, tagsStamp = stamp,
            status = null, statusStamp = NEVER,
            deleted = false, deletedStamp = NEVER,
        )
        return copy(ideas = ideas + (key to idea))
    }

    /** "idea author or admin" (§4.2) - checked against the idea's *original* creator; baseline
     * active-membership is already checked by [fold] for every op type. */
    private fun withIdeaField(env: OpEnvelope, id: ByteArray, role: Role?, mutate: (Idea) -> Idea): RoomState {
        val key = id.toKey()
        val idea = ideas[key] ?: return this
        if (!env.author.contentEquals(idea.createdBy) && !role.isAdminOrOwner()) return this
        return copy(ideas = ideas + (key to mutate(idea)))
    }

    private fun withVote(env: OpEnvelope, body: OpBody.VoteSet, stamp: LwwStamp): RoomState {
        // "author's own vote only" (§4.2) - keyed by (ideaId, author), so there's no separate
        // authorization branch: the key itself is always the caller's own.
        val key = body.ideaId.toKey() + env.author.toKey()
        val existing = votes[key]
        if (existing != null && existing.stamp > stamp) return this
        return copy(votes = votes + (key to Vote(body.value, stamp)))
    }

    private fun withCommentAdd(env: OpEnvelope, body: OpBody.CommentAdd, stamp: LwwStamp): RoomState {
        val key = body.id.toKey()
        if (comments.containsKey(key)) return this
        val comment = Comment(id = body.id, ideaId = body.ideaId, author = env.author, text = body.text, deleted = false, deletedStamp = NEVER)
        return copy(comments = comments + (key to comment))
    }

    private fun withCommentDelete(env: OpEnvelope, body: OpBody.CommentDelete, role: Role?, stamp: LwwStamp): RoomState {
        val key = body.id.toKey()
        val comment = comments[key] ?: return this
        if (!env.author.contentEquals(comment.author) && !role.isAdminOrOwner()) return this
        if (stamp <= comment.deletedStamp) return this
        return copy(comments = comments + (key to comment.copy(deleted = true, deletedStamp = stamp)))
    }

    private fun withEventCreate(env: OpEnvelope, body: OpBody.EventCreate, role: Role?, stamp: LwwStamp): RoomState {
        val key = body.id.toKey()
        if (events.containsKey(key)) return this
        if (!role.isAdminOrOwner()) return this // see the class doc comment re: the member-permission half
        val event = Event(
            id = body.id, createdBy = env.author, ideaId = body.ideaId,
            title = body.title, titleStamp = stamp,
            start = body.start, startStamp = stamp,
            end = body.end, endStamp = stamp,
            tz = body.tz, tzStamp = stamp,
            location = body.location, locationStamp = stamp,
            allDay = body.allDay, allDayStamp = stamp,
            cancelled = false, cancelledStamp = NEVER,
        )
        return copy(events = events + (key to event))
    }

    private fun withEventField(env: OpEnvelope, id: ByteArray, role: Role?, mutate: (Event) -> Event): RoomState {
        val key = id.toKey()
        val event = events[key] ?: return this
        if (!env.author.contentEquals(event.createdBy) && !role.isAdminOrOwner()) return this
        return copy(events = events + (key to mutate(event)))
    }

    private fun withEventCancel(env: OpEnvelope, body: OpBody.EventCancel, role: Role?, stamp: LwwStamp): RoomState {
        val key = body.id.toKey()
        val event = events[key] ?: return this
        if (!env.author.contentEquals(event.createdBy) && !role.isAdminOrOwner()) return this
        if (stamp <= event.cancelledStamp) return this
        return copy(events = events + (key to event.copy(cancelled = true, cancelledStamp = stamp)))
    }

    private fun withRsvp(env: OpEnvelope, body: OpBody.RsvpSet, stamp: LwwStamp): RoomState {
        val key = body.eventId.toKey() + env.author.toKey() // "own only" - same key-is-always-self reasoning as votes
        val existing = rsvps[key]
        if (existing != null && existing.stamp > stamp) return this
        return copy(rsvps = rsvps + (key to Rsvp(body.value, stamp)))
    }

    private fun withProfile(env: OpEnvelope, body: OpBody.ProfileSet, stamp: LwwStamp): RoomState {
        val key = env.author.toKey() // "own only (per-room display name)"
        val existing = profiles[key]
        if (existing != null && existing.stamp > stamp) return this
        return copy(profiles = profiles + (key to Profile(body.displayName, body.emoji, stamp)))
    }
}
