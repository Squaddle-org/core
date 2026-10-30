@file:OptIn(ExperimentalJsExport::class)

package org.squaddle.core.jsapi

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.crypto.LibsodiumCrypto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.roomId
import org.squaddle.core.ops.OpBody
import org.squaddle.core.ops.materializeRoomState
import org.squaddle.core.ops.replayMembershipHistory
import org.squaddle.core.store.LocalStore
import org.squaddle.core.store.createSqlDriver
import org.squaddle.core.sync.EntitlementOutcome
import org.squaddle.core.sync.LimitsOutcome
import org.squaddle.core.sync.ListRoomsOutcome
import org.squaddle.core.sync.PushOutcome
import org.squaddle.core.sync.SyncClient
import org.squaddle.core.sync.SyncOutcome

@JsExport
public class PushResult(public val kind: String, public val status: Int, public val code: String, public val message: String) {
    public companion object {
        public fun ok(): PushResult = PushResult("ok", 0, "", "")
        public fun waitingForRotation(): PushResult = PushResult("waiting_for_rotation", 0, "", "")
        public fun error(status: Int, code: String, message: String): PushResult = PushResult("error", status, code, message)
    }
}

@JsExport
public class SyncResult(public val ok: Boolean, public val status: Int, public val code: String, public val message: String)

@JsExport
public class RemoteRoomRefJs(public val roomId: ByteArray, public val relayHost: String)

@JsExport
public class ListRoomsResult(public val ok: Boolean, public val rooms: Array<RemoteRoomRefJs>, public val status: Int, public val code: String, public val message: String)

@JsExport
public class CreateRoomResult(public val ok: Boolean, public val roomId: ByteArray?, public val status: Int, public val code: String, public val message: String)

@JsExport
public class CreateInviteResult(public val ok: Boolean, public val inviteId: ByteArray?, public val inviteSecret: ByteArray?, public val status: Int, public val code: String, public val message: String)

/** [score] is the sum of every active member's vote value on this idea; [myVote] is the
 * caller's own vote value, or `null` if they haven't voted. [tags] is always present (empty
 * array, not `null`) - matches [org.squaddle.core.ops.Idea.tags]'s own non-nullable default. */
@JsExport
public class IdeaJs(
    public val id: ByteArray,
    public val createdBy: ByteArray,
    public val title: String,
    public val desc: String?,
    public val tags: Array<String>,
    public val score: Int,
    public val myVote: Int?,
)

@JsExport
public class CommentJs(public val id: ByteArray, public val ideaId: ByteArray, public val author: ByteArray, public val text: String)

/** [role] is one of `"owner"`, `"admin"`, `"member"`, `"pending"` (lowercased [org.squaddle.core.membership.Role.name]) -
 * pending means an approval-required join awaiting an owner/admin's `approve` (§3.3).
 * [displayName] is this member's own `profile.set` op (content-plane, not membership-log - a
 * member with no display name set yet, or a pending joiner with no epoch key to post ops at all,
 * has `null` here), mirroring android's `MembersViewModel` reading `RoomState.profiles`. */
@JsExport
public class MemberJs(public val userKey: ByteArray, public val role: String, public val displayName: String?)

/** [start]/[end] are Unix **seconds** (same unit as android's own `EventSummary`/`CalendarExport.kt`
 * - `Instant.ofEpochSecond`, not millis; multiply by 1000 before constructing a JS `Date`).
 * [myRsvp] is `"yes"`/`"no"`/`"maybe"`, or `null` if the caller hasn't RSVPed. [canCancel] mirrors
 * android's own `RoomViewModel.eventSummary`: admin/owner, or this event's own creator. */
@JsExport
public class EventJs(
    public val id: ByteArray,
    public val ideaId: ByteArray?,
    public val createdBy: ByteArray,
    public val title: String,
    public val start: Double,
    public val end: Double?,
    public val tz: String,
    public val location: String?,
    public val allDay: Boolean,
    public val canCancel: Boolean,
    public val myRsvp: String?,
    public val yesCount: Int,
    public val noCount: Int,
    public val maybeCount: Int,
)

@JsExport
public class RoomLimitsJs(
    public val ok: Boolean,
    public val tier: String?,
    public val maxMembers: Int?,
    public val maxPending: Int?,
    public val opRetentionDays: Int?,
    public val attachmentBytes: Double?,
    public val maxActiveInvites: Int?,
    public val boostedUntil: Double?,
    public val status: Int,
    public val code: String,
    public val message: String,
)

@JsExport
public class EntitlementResultJs(public val ok: Boolean, public val tier: String?, public val until: Double?, public val status: Int, public val code: String, public val message: String)

/** A handle on a running [RelaySession.connectLiveUpdates] subscription - [close] stops both the
 * WebSocket and the local poll driving it (e.g. when the UI navigates away from the room). */
@JsExport
public class LiveUpdatesHandle internal constructor(private val job: Job) {
    public fun close() {
        job.cancel()
    }
}

private fun ByteArray.toKey(): String = org.squaddle.core.encoding.Hex.encode(this)

private fun PushOutcome.toJs(): PushResult = when (this) {
    is PushOutcome.Ok -> PushResult.ok()
    is PushOutcome.WaitingForRotation -> PushResult.waitingForRotation()
    is PushOutcome.Error -> PushResult.error(status, code, message)
}

private fun SyncOutcome.toJs(): SyncResult = when (this) {
    is SyncOutcome.Ok -> SyncResult(true, 0, "", "")
    is SyncOutcome.Error -> SyncResult(false, status, code, message)
}

/**
 * One relay session, scoped to one local identity talking to one default relay host - mirrors
 * android's `AppSession`+`RealSyncGateway` combined (webclient has no separate ViewModel-gateway
 * split to preserve, so one facade class covers both). Holds real, stateful objects
 * ([LocalStore]'s in-memory `SqlJsDriver` included) across calls - constructed once via
 * [SessionApi.open], not per-call, so pulled data/cursors actually persist for the lifetime of
 * the page (ADR-0009: no cross-reload persistence yet either way).
 */
@JsExport
public class RelaySession internal constructor(
    private val sync: SyncClient,
    private val crypto: Crypto,
    private val userIdentity: UserIdentity,
    private val store: LocalStore,
) {
    private val scope = CoroutineScope(SupervisorJob())

    public suspend fun registerDevice(): PushResult = sync.publishDeviceCert().toJs()

    public suspend fun createRoom(): CreateRoomResult {
        val nonce = crypto.randomBytes(16)
        val room = roomId(crypto, userIdentity.userKey, nonce)
        val outcome = sync.createRoom(room, nonce)
        return if (outcome == PushOutcome.Ok) {
            CreateRoomResult(true, room, 0, "", "")
        } else {
            val error = outcome as PushOutcome.Error
            CreateRoomResult(false, null, error.status, error.code, error.message)
        }
    }

    /** For an open (non-approval) invite, [CreateInviteResult.inviteSecret] carries the secret
     * to put in the invite link's URL fragment (never logged, never sent back to the relay -
     * PROTOCOL.md §3.5). `null` for an approval-required invite - "no envelope exists" by design,
     * nothing to carry. [roomName], if given, is sealed into the invite envelope itself (not
     * sent in the clear) so a joiner can preview it via [peekInviteRoomName] before committing -
     * mirrors android's `RealSyncGateway.createInvite` threading its local known-rooms display
     * name the same way. */
    public suspend fun createInvite(roomId: ByteArray, requiresApproval: Boolean, expiresAt: Double?, maxUses: Int?, roomName: String? = null): CreateInviteResult {
        val inviteId = crypto.randomBytes(16)
        val outcome = sync.createInvite(roomId, inviteId, requiresApproval, expiresAt?.toLong(), maxUses, roomName)
        if (outcome != PushOutcome.Ok) {
            val error = outcome as PushOutcome.Error
            return CreateInviteResult(false, null, null, error.status, error.code, error.message)
        }
        if (requiresApproval) return CreateInviteResult(true, inviteId, null, 0, "", "")
        val secret = store.inviteSecretsFor(roomId).firstOrNull { it.invite_id.contentEquals(inviteId) }?.secret
        return CreateInviteResult(true, inviteId, secret, 0, "", "")
    }

    public suspend fun listMyRooms(): ListRoomsResult {
        val outcome = sync.listMyRooms()
        return when (outcome) {
            is ListRoomsOutcome.Ok -> ListRoomsResult(true, outcome.rooms.map { RemoteRoomRefJs(it.roomId, it.relayHost) }.toTypedArray(), 0, "", "")
            is ListRoomsOutcome.Error -> ListRoomsResult(false, emptyArray(), outcome.status, outcome.code, outcome.message)
        }
    }

    /** Open (non-approval) invites only, matching [SyncClient.joinViaLink]'s own signature
     * exactly - approval-required invites (PROTOCOL.md §3.5: no envelope exists for those) have
     * no equivalent path on [SyncClient] itself to wrap (android's own `RealSyncGateway` builds
     * that path by hand from other public `SyncClient` methods); M5a's E2E scope is the open-
     * invite flow, so that gap is left explicit here rather than duplicated or faked. */
    public suspend fun joinViaLink(roomId: ByteArray, inviteId: ByteArray, inviteSecret: ByteArray): PushResult =
        sync.joinViaLink(roomId, inviteId, inviteSecret).toJs()

    /** The approval-required counterpart of [joinViaLink] - see [SyncClient.joinPendingApproval]'s
     * own doc comment. No room name to preview beforehand (no envelope exists for these invites
     * at all); the joiner shows as `"pending"` (see [MemberJs.role]) until approved. */
    public suspend fun joinPendingApproval(roomId: ByteArray, inviteId: ByteArray): PushResult =
        sync.joinPendingApproval(roomId, inviteId).toJs()

    /** `null` if there's no secret to decrypt with (approval-required invite - §3.5, no
     * envelope exists), the envelope fetch failed, or it didn't decrypt. Read-only: safe to
     * call before deciding to join. */
    public suspend fun peekInviteRoomName(roomId: ByteArray, inviteId: ByteArray, inviteSecret: ByteArray): String? =
        sync.peekInviteRoomName(roomId, inviteId, inviteSecret)

    public suspend fun pull(roomId: ByteArray): SyncResult = sync.pull(roomId).toJs()

    /** Pure local replay (no network - call [pull] first for fresh data), sorted by [IdeaJs.score]
     * descending to match the Room screen's "ideas by score" ordering. Deleted ideas are
     * filtered out - M5a has no idea-delete UI, but a future client could still produce one. */
    public suspend fun listIdeas(roomId: ByteArray): Array<IdeaJs> {
        val state = materializeRoomState(crypto, sync, store, roomId)
        return state.ideas.values.filterNot { it.deleted }
            .map { idea ->
                val score = state.votesForIdea(idea.id).sumOf { it.value }
                val myVote = state.myVoteForIdea(idea.id, userIdentity.userKey)?.value
                IdeaJs(idea.id, idea.createdBy, idea.title, idea.desc, idea.tags.toTypedArray(), score, myVote)
            }
            .sortedByDescending { it.score }
            .toTypedArray()
    }

    /** Pure local replay (no network - call [pull] first for fresh data). */
    public suspend fun listComments(roomId: ByteArray, ideaId: ByteArray): Array<CommentJs> {
        val state = materializeRoomState(crypto, sync, store, roomId)
        return state.comments.values
            .filter { it.ideaId.contentEquals(ideaId) && !it.deleted }
            .map { CommentJs(it.id, it.ideaId, it.author, it.text) }
            .toTypedArray()
    }

    /** Enqueues locally and makes a best-effort push - `false` only if the room's current epoch
     * key isn't unwrapped yet (shouldn't happen after at least one successful [pull]). A failed
     * push leaves the op queued for the next [pull]/push cycle to retry, same as android's
     * `RealSyncGateway.enqueueAndPush`. */
    public suspend fun createIdea(roomId: ByteArray, title: String, desc: String?): Boolean =
        enqueueAndPush(roomId, OpBody.IdeaCreate(crypto.randomBytes(16), title, desc, emptyList()))

    public suspend fun vote(roomId: ByteArray, ideaId: ByteArray, value: Int): Boolean =
        enqueueAndPush(roomId, OpBody.VoteSet(ideaId, value))

    public suspend fun addComment(roomId: ByteArray, ideaId: ByteArray, text: String): Boolean =
        enqueueAndPush(roomId, OpBody.CommentAdd(crypto.randomBytes(16), ideaId, text))

    private suspend fun enqueueAndPush(roomId: ByteArray, body: OpBody): Boolean {
        if (!sync.enqueueOp(roomId, body)) return false
        try {
            sync.push(roomId)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // Already queued in the outbox - a later pull()/push() retries it.
        }
        return true
    }

    /** Pure local replay (no network - call [pull] first for fresh data). Includes `"pending"`
     * members (approval-required joins awaiting approval, §3.3) - read-only, no UI gating
     * decisions are made off of this list in M5a. */
    public suspend fun listMembers(roomId: ByteArray): Array<MemberJs> {
        val (history, _) = replayMembershipHistory(crypto, store, roomId)
        val profiles = materializeRoomState(crypto, sync, store, roomId).profiles
        return history.current.members()
            .map { MemberJs(it.user, it.role.name.lowercase(), profiles[it.user.toKey()]?.displayName) }
            .toTypedArray()
    }

    public suspend fun editIdea(roomId: ByteArray, id: ByteArray, field: String, value: String?): Boolean =
        enqueueAndPush(roomId, OpBody.IdeaSet(id, field, value))

    public suspend fun deleteIdea(roomId: ByteArray, id: ByteArray): Boolean =
        enqueueAndPush(roomId, OpBody.IdeaDelete(id))

    public suspend fun deleteComment(roomId: ByteArray, id: ByteArray): Boolean =
        enqueueAndPush(roomId, OpBody.CommentDelete(id))

    /** This caller's own role in [roomId], lowercased (see [MemberJs.role]) - `null` if not a
     * member at all (shouldn't normally happen for a room the UI already has open). Pure local
     * replay, same as [listMembers]. */
    public suspend fun myRole(roomId: ByteArray): String? {
        val (history, _) = replayMembershipHistory(crypto, store, roomId)
        return history.current.roleOf(userIdentity.userKey)?.name?.lowercase()
    }

    /** Whether this caller is currently allowed to create an event in [roomId] - admin/owner
     * always can; a plain member can only if the room's `membersCanCreateEvents` setting (§3.3
     * row 11 field 1, default on) allows it at the room's current epoch. Mirrors android's
     * `RoomViewModel`'s own `canCreateEvent` computation exactly. */
    public suspend fun canCreateEvent(roomId: ByteArray): Boolean {
        val (history, _) = replayMembershipHistory(crypto, store, roomId)
        val role = history.current.roleOf(userIdentity.userKey)
        return role == org.squaddle.core.membership.Role.ADMIN || role == org.squaddle.core.membership.Role.OWNER ||
            (role == org.squaddle.core.membership.Role.MEMBER && history.membersCanCreateEventsAt(history.current.epoch))
    }

    /** Pure local replay (no network - call [pull] first for fresh data). Cancelled events are
     * filtered out, sorted by start time - mirrors android's `RoomViewModel` exactly. */
    public suspend fun listEvents(roomId: ByteArray): Array<EventJs> {
        val myKeyHex = userIdentity.userKey.toKey()
        val (history, _) = replayMembershipHistory(crypto, store, roomId)
        val role = history.current.roleOf(userIdentity.userKey)
        val isAdminOrOwner = role == org.squaddle.core.membership.Role.ADMIN || role == org.squaddle.core.membership.Role.OWNER
        val state = materializeRoomState(crypto, sync, store, roomId)
        return state.events.values
            .filterNot { it.cancelled }
            .map { event ->
                val eventIdHex = event.id.toKey()
                val forThisEvent = state.rsvps.filterKeys { it.startsWith(eventIdHex) }.values
                EventJs(
                    id = event.id, ideaId = event.ideaId, createdBy = event.createdBy, title = event.title,
                    start = event.start.toDouble(), end = event.end?.toDouble(), tz = event.tz, location = event.location, allDay = event.allDay,
                    canCancel = isAdminOrOwner || event.createdBy.contentEquals(userIdentity.userKey),
                    myRsvp = state.rsvps[eventIdHex + myKeyHex]?.value,
                    yesCount = forThisEvent.count { it.value == "yes" },
                    noCount = forThisEvent.count { it.value == "no" },
                    maybeCount = forThisEvent.count { it.value == "maybe" },
                )
            }
            .sortedBy { it.start }
            .toTypedArray()
    }

    public suspend fun createEvent(
        roomId: ByteArray,
        ideaId: ByteArray?,
        title: String,
        start: Double,
        end: Double?,
        tz: String,
        location: String?,
        allDay: Boolean,
    ): PushResult = sync.createEvent(roomId, ideaId, title, start.toLong(), end?.toLong(), tz, location, allDay).toJs()

    public suspend fun cancelEvent(roomId: ByteArray, id: ByteArray): PushResult = sync.cancelEvent(roomId, id).toJs()

    /** [value] is `"yes"`, `"no"`, or `"maybe"` (PROTOCOL.md §4.3). */
    public suspend fun rsvp(roomId: ByteArray, eventId: ByteArray, value: String): PushResult = sync.rsvp(roomId, eventId, value).toJs()

    public suspend fun setProfile(roomId: ByteArray, displayName: String, emoji: String?): PushResult =
        sync.setProfile(roomId, displayName, emoji).toJs()

    public suspend fun kick(roomId: ByteArray, target: ByteArray): PushResult = sync.kick(roomId, target).toJs()

    public suspend fun setRole(roomId: ByteArray, target: ByteArray, role: String): PushResult = sync.setRole(roomId, target, role).toJs()

    public suspend fun transferOwner(roomId: ByteArray, target: ByteArray): PushResult = sync.transferOwner(roomId, target).toJs()

    public suspend fun approve(roomId: ByteArray, target: ByteArray): PushResult = sync.approve(roomId, target).toJs()

    public suspend fun reject(roomId: ByteArray, target: ByteArray): PushResult = sync.reject(roomId, target).toJs()

    public suspend fun getLimits(roomId: ByteArray): RoomLimitsJs {
        return when (val outcome = sync.getLimits(roomId)) {
            is LimitsOutcome.Ok -> {
                val l = outcome.limits
                RoomLimitsJs(true, l.tier, l.maxMembers, l.maxPending, l.opRetentionDays, l.attachmentBytes?.toDouble(), l.maxActiveInvites, l.boostedUntil?.toDouble(), 0, "", "")
            }
            is LimitsOutcome.Error -> RoomLimitsJs(false, null, null, null, null, null, null, null, outcome.status, outcome.code, outcome.message)
        }
    }

    public suspend fun redeemVoucher(roomId: ByteArray, code: String): EntitlementResultJs {
        return when (val outcome = sync.redeemVoucher(roomId, code)) {
            is EntitlementOutcome.Ok -> EntitlementResultJs(true, outcome.tier, outcome.until?.toDouble(), 0, "", "")
            is EntitlementOutcome.Error -> EntitlementResultJs(false, null, null, outcome.status, outcome.code, outcome.message)
        }
    }

    /** `null` if push isn't configured on this relay, or it's unreachable - see [SyncClient.vapidPublicKey]. */
    public suspend fun vapidPublicKey(): String? = sync.vapidPublicKey()

    /** Registers this browser's Web Push subscription endpoint (`PushSubscription.endpoint`) -
     * the Web Push equivalent of android's UnifiedPush distributor endpoint. */
    public suspend fun registerPushEndpoint(endpoint: String): PushResult = sync.registerPushEndpoint(endpoint).toJs()

    public suspend fun unregisterPush(): PushResult = sync.unregisterPush().toJs()

    /**
     * Subscribes to [roomId]'s live updates (PROTOCOL.md §6) and invokes [onChanged] whenever
     * new data actually lands locally. Two cooperating loops, same split android's
     * `RealSyncGateway.connectLiveUpdates` uses: core's own [SyncClient.connectLiveUpdates]
     * suspends for the socket's lifetime and already calls `pull()` on every server push, but
     * exposes no "something changed" signal of its own; a second, local-SQLite-only poll (no
     * network) notices when that pull actually landed new data and fires [onChanged] - simpler
     * than adding a callback to core's socket loop itself for one caller. Call [LiveUpdatesHandle.close]
     * when the UI navigates away (e.g. leaves the room screen) to stop both loops.
     */
    public fun connectLiveUpdates(roomId: ByteArray, onChanged: () -> Unit): LiveUpdatesHandle {
        val job = scope.launch {
            launch {
                try {
                    sync.connectLiveUpdates(listOf(roomId))
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    // Best-effort: the local poll below still notices new data from a later pull().
                }
            }
            launch {
                var lastLogIndex = store.maxLogIndex(roomId)
                var lastOpsCursor = store.maxOpsCursor(roomId)
                while (true) {
                    delay(1500)
                    val logIndex = store.maxLogIndex(roomId)
                    val opsCursor = store.maxOpsCursor(roomId)
                    if (logIndex != lastLogIndex || opsCursor != lastOpsCursor) {
                        lastLogIndex = logIndex
                        lastOpsCursor = opsCursor
                        onChanged()
                    }
                }
            }
        }
        return LiveUpdatesHandle(job)
    }
}

@JsExport
public object SessionApi {
    public suspend fun open(
        entropy: ByteArray,
        devicePublicKey: ByteArray,
        deviceSecretKey: ByteArray,
        deviceCertUser: ByteArray,
        deviceCertUserBox: ByteArray,
        deviceCertLabel: String,
        deviceCertIssuedAt: Double,
        deviceCertSig: ByteArray,
        relayHost: String,
        /** `false` only for a relay reached directly without a TLS-terminating reverse proxy in
         * front (local dev/test against the relay binary itself, which only ever speaks plain
         * HTTP - mirrors [SyncClient]'s own constructor default/doc comment). */
        tls: Boolean = true,
    ): RelaySession {
        val crypto = LibsodiumCrypto.create()
        val identity = UserIdentity.fromEntropy(crypto, entropy)
        val device = KeyPair(devicePublicKey, deviceSecretKey)
        val cert = DeviceCert(
            user = deviceCertUser, userBox = deviceCertUserBox, device = devicePublicKey,
            label = deviceCertLabel, issuedAt = deviceCertIssuedAt.toLong(), sig = deviceCertSig,
        )
        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, relayHost, identity, device, cert, tls = tls)
        return RelaySession(sync, crypto, identity, store)
    }
}
