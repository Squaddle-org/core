@file:OptIn(ExperimentalJsExport::class)

package org.squaddle.core.jsapi

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.roomId
import org.squaddle.core.ops.OpBody
import org.squaddle.core.ops.materializeRoomState
import org.squaddle.core.store.LocalStore
import org.squaddle.core.store.createSqlDriver
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
