@file:OptIn(ExperimentalEncodingApi::class)

package org.squaddle.core.sync

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.websocket.Frame
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.encoding.Base32
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.EpochKeys
import org.squaddle.core.membership.InviteEnvelope
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipState
import org.squaddle.core.membership.MembershipStateImpl
import org.squaddle.core.membership.Role
import org.squaddle.core.membership.StoredEntry
import org.squaddle.core.ops.OpBody
import org.squaddle.core.ops.OpEnvelope
import org.squaddle.core.ops.decodeOpBody
import org.squaddle.core.ops.encode
import org.squaddle.core.store.LocalStore
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Serializable
private data class RelayErrorBody(val code: String, val message: String, val head: String? = null, val epoch: Long? = null)

@Serializable
private data class AppendedBody(val index: Long, val rts: Long)

/** PROTOCOL.md §6's shape, reused for `/ws` live push (relay-api.yaml: `{"r":"<b32 roomId>",
 * "c":<cursor>,"k":"ops|log"}`). */
@Serializable
private data class WsEvent(val r: String, val c: Long, val k: String)

@Serializable
private data class WsSubscribe(val sub: List<String>)

public sealed interface SyncOutcome {
    public data object Ok : SyncOutcome
    public data class Error(val status: Int, val code: String, val message: String) : SyncOutcome
}

public sealed interface PushOutcome {
    public data object Ok : PushOutcome

    /** PROTOCOL.md §3.4: a non-admin/owner device must simply wait for the next successful pull
     * to observe `rotationPending` go false (someone else's `epochRotate`), then retry - this is
     * not a hard failure. */
    public data object WaitingForRotation : PushOutcome
    public data class Error(val status: Int, val code: String, val message: String) : PushOutcome
}

private fun ByteArray.toKey(): String = joinToString("") { "%02x".format(it) }

/**
 * PROTOCOL.md §4/§5 sync client: pulls the membership log + op-log into [store], decrypts+tracks
 * epoch keys observed along the way, and pushes locally-queued ops/log-entries with the retry
 * behavior §3.3/§3.4 require. One instance is scoped to a single local device identity talking to
 * a single relay host - callers needing multiple rooms just call the room-scoped methods with
 * different `room` byte arrays, since nothing here is room-specific state.
 */
public class SyncClient(
    private val crypto: Crypto,
    private val store: LocalStore,
    private val relayHost: String,
    private val userIdentity: UserIdentity,
    private val device: KeyPair,
    private val deviceCert: DeviceCert,
    private val httpClient: HttpClient = createHttpClient(),
    /** `false` only for a relay reached directly without a TLS-terminating reverse proxy in
     * front (local dev/test runs against the relay binary itself, which only ever speaks plain
     * HTTP - see relay/cmd/relay/main.go). Every real deployment terminates TLS upstream, so this
     * defaults to `true`. */
    private val tls: Boolean = true,
) {
    private val httpScheme: String get() = if (tls) "https" else "http"
    private val wsScheme: String get() = if (tls) "wss" else "ws"

    // room.toKey() -> epoch -> epochKey. Pure in-memory cache over `store`'s own epoch_keys
    // table (the real source of truth) - NOT every epoch key is re-derivable from the log alone:
    // a member who joined via an open invite got theirs from the invite envelope, which leaves no
    // trace in any log entry and typically stops existing once the invite is gone, so every key,
    // however learned, is persisted on [registerEpochKey].
    private val epochKeys = mutableMapOf<String, MutableMap<Long, ByteArray>>()

    public fun registerEpochKey(room: ByteArray, epoch: Long, key: ByteArray) {
        epochKeys.getOrPut(room.toKey()) { mutableMapOf() }[epoch] = key
        store.insertEpochKey(room, epoch, key)
    }

    public fun epochKeyFor(room: ByteArray, epoch: Long): ByteArray? {
        epochKeys[room.toKey()]?.get(epoch)?.let { return it }
        val persisted = store.epochKeyRowFor(room, epoch)?.key ?: return null
        epochKeys.getOrPut(room.toKey()) { mutableMapOf() }[epoch] = persisted
        return persisted
    }

    private fun b64Url(bytes: ByteArray): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)

    private fun path(suffix: String): String = "/v1$suffix"

    private suspend fun authedRequest(method: HttpMethod, pathAndQuery: String, body: ByteArray = ByteArray(0)): HttpResponse {
        val ts = nowUnixSeconds()
        val nonce = crypto.randomBytes(16)
        val header = RequestAuth.headerValue(crypto, device.secretKey, device.publicKey, method.value, pathAndQuery, ts, nonce, body)
        return httpClient.request("$httpScheme://$relayHost$pathAndQuery") {
            this.method = method
            header("Authorization", header)
            if (method != HttpMethod.Get) {
                header("Content-Type", "application/cbor")
                setBody(body)
            }
        }
    }

    private fun parseError(bytes: ByteArray): RelayErrorBody? =
        try {
            Json.decodeFromString(RelayErrorBody.serializer(), bytes.decodeToString())
        } catch (e: Exception) {
            null
        }

    /** Replays this room's stored log once to get its current [MembershipState]. Tolerates (skips,
     * does not throw on) a reject - should never actually happen against a well-behaved relay,
     * since every stored entry already passed server-side validation before being pulled. */
    private fun replayMembershipState(room: ByteArray): MembershipState {
        var state: MembershipState = MembershipStateImpl.empty(crypto)
        for (row in store.logEntriesFrom(room, 0L)) {
            val entry = LogEntry.decode(row.entry_cbor) ?: continue
            state = state.apply(StoredEntry(entry, row.rts)).getOrElse { state }
        }
        return state
    }

    /** Re-derives this device's epoch keys from the room's already-locally-stored log, without
     * touching the network. [epochKeys] is in-memory only (see its own doc comment) - a process
     * restart needs this once per room before anything that decrypts ops, since [pull] only ever
     * re-observes entries newer than the local cursor, not ones already on disk from a previous
     * run. */
    public fun rehydrateEpochKeys(room: ByteArray) {
        for (row in store.logEntriesFrom(room, 0L)) {
            val entry = LogEntry.decode(row.entry_cbor) ?: continue
            observeEpochWraps(room, entry)
        }
    }

    /** Unwraps any epoch key addressed to this device's user from a just-observed log entry:
     * genesis's own `epoch0Wrapped` (field 2, owner only), `approve`'s `wrappedEpochKey` (field 1,
     * only if the approved user is us), or `epochRotate`'s per-user wrap array (field 1). */
    private fun observeEpochWraps(room: ByteArray, entry: LogEntry) {
        fun tryUnwrap(sealed: ByteArray) {
            val wrap = EpochKeys.open(crypto, userIdentity.box, sealed) ?: return
            if (wrap.room.contentEquals(room)) registerEpochKey(room, wrap.epoch, wrap.epochKey)
        }
        when (entry.type) {
            EntryType.GENESIS -> {
                if (!entry.author.contentEquals(userIdentity.userKey)) return
                (entry.body.entries[2L] as? CborValue.Bytes)?.value?.let(::tryUnwrap)
            }
            EntryType.APPROVE -> {
                val target = (entry.body.entries[0L] as? CborValue.Bytes)?.value ?: return
                if (!target.contentEquals(userIdentity.userKey)) return
                (entry.body.entries[1L] as? CborValue.Bytes)?.value?.let(::tryUnwrap)
            }
            EntryType.EPOCH_ROTATE -> {
                val wraps = (entry.body.entries[1L] as? CborValue.Array)?.items ?: return
                for (w in wraps) {
                    val m = (w as? CborValue.Map)?.entries ?: continue
                    (m[1L] as? CborValue.Bytes)?.value?.let(::tryUnwrap)
                }
            }
            else -> {}
        }
    }

    private fun decodeLogResponse(bytes: ByteArray): List<Pair<ByteArray, Long>> {
        val top = try {
            CanonicalCborCodec.decode(bytes) as? CborValue.Array ?: return emptyList()
        } catch (e: CborFormatException) {
            return emptyList()
        }
        return top.items.mapNotNull { item ->
            val m = (item as? CborValue.Map)?.entries ?: return@mapNotNull null
            val entryCbor = (m[0L] as? CborValue.Bytes)?.value ?: return@mapNotNull null
            val rts = (m[1L] as? CborValue.UInt)?.value ?: return@mapNotNull null
            entryCbor to rts
        }
    }

    private fun decodeOpsResponse(bytes: ByteArray): Pair<List<Pair<Long, ByteArray>>, Long> {
        val top = try {
            CanonicalCborCodec.decode(bytes) as? CborValue.Map ?: return emptyList<Pair<Long, ByteArray>>() to 0L
        } catch (e: CborFormatException) {
            return emptyList<Pair<Long, ByteArray>>() to 0L
        }
        val items = (top.entries[0L] as? CborValue.Array)?.items.orEmpty().mapNotNull { item ->
            val m = (item as? CborValue.Map)?.entries ?: return@mapNotNull null
            val cursor = (m[0L] as? CborValue.UInt)?.value ?: return@mapNotNull null
            val envelope = (m[1L] as? CborValue.Bytes)?.value ?: return@mapNotNull null
            cursor to envelope
        }
        val next = (top.entries[1L] as? CborValue.UInt)?.value ?: 0L
        return items to next
    }

    /** Pulls new log entries + ops since the last saved cursor for [room]. */
    public suspend fun pull(room: ByteArray): SyncOutcome {
        val logOutcome = pullLog(room)
        if (logOutcome is SyncOutcome.Error) return logOutcome
        return pullOps(room)
    }

    /** The log half of [pull] on its own - PROTOCOL.md §5 only gates ops/snapshots reads on
     * membership ("Read access to ops/snapshots: device's user is member/admin/owner"), the log
     * itself has no such restriction (relay's own `getLog` has no membership check, unlike
     * `getOps`) - a brand-new joiner with no membership yet still needs to read the log to learn
     * the current head before it can sign its own `join` entry's index/prev. [joinViaLink] uses
     * this instead of the full [pull] for exactly that reason. */
    public suspend fun pullLog(room: ByteArray): SyncOutcome {
        val existingCursor = store.cursorFor(room)
        val fromIndex = (existingCursor?.last_log_index ?: -1L) + 1

        val logResp = authedRequest(HttpMethod.Get, path("/rooms/${b64Url(room)}/log?from=$fromIndex"))
        if (logResp.status != HttpStatusCode.OK) return errorOutcome(logResp)
        var lastLogIndex = existingCursor?.last_log_index ?: -1L
        for ((entryCbor, rts) in decodeLogResponse(logResp.bodyAsBytes())) {
            val entry = LogEntry.decode(entryCbor) ?: continue
            store.insertLogEntry(room, entry.index, entryCbor, rts)
            if (entry.index > lastLogIndex) lastLogIndex = entry.index
            observeEpochWraps(room, entry)
        }
        store.upsertCursor(room, lastLogIndex, existingCursor?.last_ops_cursor ?: 0L)
        return SyncOutcome.Ok
    }

    /** The ops half of [pull] on its own - members only (§5), unlike [pullLog]. */
    public suspend fun pullOps(room: ByteArray): SyncOutcome {
        val existingCursor = store.cursorFor(room)
        val afterCursor = existingCursor?.last_ops_cursor ?: 0L

        val opsResp = authedRequest(HttpMethod.Get, path("/rooms/${b64Url(room)}/ops?after=$afterCursor"))
        if (opsResp.status != HttpStatusCode.OK) return errorOutcome(opsResp)
        val (ops, next) = decodeOpsResponse(opsResp.bodyAsBytes())
        for ((opCursor, envelopeCbor) in ops) {
            val env = OpEnvelope.decode(envelopeCbor) ?: continue
            store.insertOp(room, opCursor, env.opId(crypto), env.device, env.seq, envelopeCbor)
            store.upsertDeviceSeq(room, env.device, env.seq)
        }
        store.upsertCursor(room, existingCursor?.last_log_index ?: -1L, next)
        return SyncOutcome.Ok
    }

    private suspend fun errorOutcome(resp: HttpResponse): SyncOutcome.Error {
        val err = parseError(resp.bodyAsBytes())
        return SyncOutcome.Error(resp.status.value, err?.code ?: "invalid", err?.message ?: "unparseable error body")
    }

    /** `POST /v1/rooms` (relay-api.yaml) - a distinct one-shot endpoint from [appendLogEntry]'s
     * `/log` (no `stale_head` concept: a room id either doesn't exist yet or already does).
     * Generates a fresh epoch-0 key, wraps it for the owner (genesis's own `epoch0Wrapped`,
     * §3.3 row 0), and registers it locally on success. [roomNonce] must be the same bytes used
     * to derive [room] via `org.squaddle.core.membership.roomId` - the relay re-derives and
     * checks this. */
    public suspend fun createRoom(room: ByteArray, roomNonce: ByteArray): PushOutcome {
        val epochKey = crypto.randomBytes(32)
        val sealed = EpochKeys.seal(crypto, userIdentity.userBoxKey, room, 0L, epochKey)
        val body = CborValue.Map(mapOf(0L to CborValue.Bytes(roomNonce), 1L to CborValue.Text(relayHost), 2L to CborValue.Bytes(sealed)))
        val entry = LogEntry.sign(crypto, device.secretKey, room, 0L, null, userIdentity.userKey, deviceCert, EntryType.GENESIS, body, nowUnixSeconds())
        val fullCbor = CanonicalCborCodec.encode(entry.toFullCbor())
        val resp = authedRequest(HttpMethod.Post, path("/rooms"), fullCbor)
        if (resp.status != HttpStatusCode.Created) {
            val err = parseError(resp.bodyAsBytes())
            return PushOutcome.Error(resp.status.value, err?.code ?: "invalid", err?.message ?: "room creation failed")
        }
        val rts = try {
            Json.decodeFromString(AppendedBody.serializer(), resp.bodyAsBytes().decodeToString()).rts
        } catch (e: Exception) {
            nowUnixSeconds()
        }
        store.insertLogEntry(room, 0L, fullCbor, rts)
        store.upsertCursor(room, 0L, 0L)
        registerEpochKey(room, 0L, epochKey)
        return PushOutcome.Ok
    }

    /** Appends one membership-log entry, retrying against a fresh head on `409 stale_head`
     * (PROTOCOL.md §3.3: "the relay accepts an append only if prev == currentHead; else 409,
     * client refetches and retries"). [buildEntry] is handed the index/prev to sign against on
     * each attempt, since a stale-head retry fundamentally needs a freshly-signed entry, not a
     * resend of the same bytes. */
    public suspend fun appendLogEntry(room: ByteArray, maxRetries: Int = 3, buildEntry: (index: Long, prev: ByteArray?) -> LogEntry): PushOutcome {
        repeat(maxRetries) {
            val cursor = store.cursorFor(room)
            val nextIndex = (cursor?.last_log_index ?: -1L) + 1
            val prevHash = if (nextIndex == 0L) {
                null
            } else {
                store.logEntriesFrom(room, nextIndex - 1).firstOrNull { it.idx == nextIndex - 1 }
                    ?.let { LogEntry.decode(it.entry_cbor)?.entryHash(crypto) }
            }
            val entry = buildEntry(nextIndex, prevHash)
            val resp = authedRequest(HttpMethod.Post, path("/rooms/${b64Url(room)}/log"), CanonicalCborCodec.encode(entry.toFullCbor()))
            if (resp.status == HttpStatusCode.Created) {
                val rts = try {
                    Json.decodeFromString(AppendedBody.serializer(), resp.bodyAsBytes().decodeToString()).rts
                } catch (e: Exception) {
                    nowUnixSeconds()
                }
                store.insertLogEntry(room, entry.index, CanonicalCborCodec.encode(entry.toFullCbor()), rts)
                store.upsertCursor(room, entry.index, cursor?.last_ops_cursor ?: 0L)
                observeEpochWraps(room, entry)
                return PushOutcome.Ok
            }
            val err = parseError(resp.bodyAsBytes()) ?: return PushOutcome.Error(resp.status.value, "invalid", "unparseable error body")
            if (err.code != "stale_head") return PushOutcome.Error(resp.status.value, err.code, err.message)
            pull(room) // refresh local head; the next loop iteration re-signs against it
        }
        return PushOutcome.Error(409, "stale_head", "exceeded retry budget ($maxRetries attempts)")
    }

    private fun localMaxLamportSeen(room: ByteArray): Long {
        val fromOps = store.opsAfter(room, 0L).mapNotNull { OpEnvelope.decode(it.envelope_cbor)?.lamport }.maxOrNull() ?: 0L
        val fromOutbox = store.outboxFor(room).maxOfOrNull { it.lamport } ?: 0L
        return maxOf(fromOps, fromOutbox)
    }

    /** Queues a new content-plane op locally (outbox), under the room's current epoch key.
     * `false` if the current epoch's key hasn't been unwrapped yet (shouldn't happen for an
     * active member who has pulled at least once since their most recent `approve`/`epochRotate`). */
    public fun enqueueOp(room: ByteArray, body: OpBody): Boolean {
        val epoch = replayMembershipState(room).epoch
        val key = epochKeyFor(room, epoch) ?: return false
        val mySeq = (store.deviceSeqsFor(room).firstOrNull { it.device.contentEquals(device.publicKey) }?.seq ?: 0L) + 1
        val lamport = localMaxLamportSeen(room) + 1
        val nonce = crypto.randomBytes(24)
        val env = OpEnvelope.create(crypto, device.secretKey, key, room, epoch, userIdentity.userKey, device.publicKey, mySeq, lamport, body, nonce)
        val localOrder = (store.maxOutboxLocalOrder(room) ?: 0L) + 1
        store.insertOutbox(room, localOrder, epoch, mySeq, lamport, nonce, body.encode(), CanonicalCborCodec.encode(env.toFullCbor()))
        store.upsertDeviceSeq(room, device.publicKey, mySeq)
        return true
    }

    /** Re-encrypts every still-outstanding outbox entry under [room]'s current epoch key, in
     * place - `false` if that key hasn't been unwrapped yet (caller should pull() first). */
    private fun reencryptOutboxForNewEpoch(room: ByteArray): Boolean {
        val currentEpoch = replayMembershipState(room).epoch
        val key = epochKeyFor(room, currentEpoch) ?: return false
        for (entry in store.outboxFor(room)) {
            if (entry.epoch == currentEpoch) continue
            val body = decodeOpBody(entry.body_cbor) ?: continue
            val newNonce = crypto.randomBytes(24)
            val newEnv = OpEnvelope.create(crypto, device.secretKey, key, room, currentEpoch, userIdentity.userKey, device.publicKey, entry.seq, entry.lamport, body, newNonce)
            store.replaceOutboxEnvelope(room, entry.local_order, currentEpoch, newNonce, CanonicalCborCodec.encode(newEnv.toFullCbor()))
        }
        return true
    }

    /** Pushes every outstanding outbox op for [room] as one batch.
     * - `409 stale_epoch`: re-encrypts the outbox under the new epoch key (unwrapped via a fresh
     *   [pull]) and retries once.
     * - `409 rotation_required` (ADR-0012): if this device's user currently holds owner/admin,
     *   authors+pushes the missing `epochRotate` itself (§3.4: "Clients MUST rotate automatically
     *   when they author a remove" - generalized here to "whichever admin/owner notices first",
     *   since any of them may clear `rotationPending`) and retries; otherwise returns
     *   [PushOutcome.WaitingForRotation] - the caller should simply [pull] again later. */
    public suspend fun push(room: ByteArray, allowRetry: Boolean = true): PushOutcome {
        val pending = store.outboxFor(room)
        if (pending.isEmpty()) return PushOutcome.Ok

        val batch = CanonicalCborCodec.encode(CborValue.Array(pending.map { CanonicalCborCodec.decode(it.envelope_cbor) }))
        val resp = authedRequest(HttpMethod.Post, path("/rooms/${b64Url(room)}/ops"), batch)
        if (resp.status == HttpStatusCode.Created) {
            for (entry in pending) store.deleteOutboxEntry(room, entry.local_order)
            return PushOutcome.Ok
        }

        val err = parseError(resp.bodyAsBytes()) ?: return PushOutcome.Error(resp.status.value, "invalid", "unparseable error body")
        if (!allowRetry) return PushOutcome.Error(resp.status.value, err.code, err.message)

        when (err.code) {
            "stale_epoch" -> {
                pull(room) // picks up the epochRotate entry and unwraps the new key
                if (reencryptOutboxForNewEpoch(room)) return push(room, allowRetry = false)
            }
            "rotation_required" -> {
                val role = replayMembershipState(room).roleOf(userIdentity.userKey)
                if (role == Role.OWNER || role == Role.ADMIN) {
                    val rotateOutcome = autoRotate(room)
                    if (rotateOutcome == PushOutcome.Ok) {
                        // autoRotate just moved the room to a new epoch - every still-queued op
                        // was encrypted under the old one and would otherwise immediately bounce
                        // off a (correct) stale_epoch on the retry.
                        reencryptOutboxForNewEpoch(room)
                        return push(room, allowRetry = false)
                    }
                    return rotateOutcome
                }
                return PushOutcome.WaitingForRotation
            }
        }
        return PushOutcome.Error(resp.status.value, err.code, err.message)
    }

    /** Collects each current member's `userBoxKey` from the DeviceCert embedded in their most
     * recent authored log entry (every cert carries the author's actual per-user box key, not a
     * per-device one, per §2.1/§2.2). */
    private fun collectUserBoxKeys(room: ByteArray): Map<String, ByteArray> {
        val map = mutableMapOf<String, ByteArray>()
        for (row in store.logEntriesFrom(room, 0L)) {
            val entry = LogEntry.decode(row.entry_cbor) ?: continue
            map[entry.author.toKey()] = entry.cert.userBox
        }
        return map
    }

    /** Authors and pushes an `epochRotate` entry wrapping a fresh epoch key for every current
     * non-pending member (§3.3 row 10), then re-uploads every active open invite's envelope under
     * the new key (§3.5: "Admins MUST re-upload envelopes of all active invites after every
     * epochRotate"). Caller must already hold owner/admin - [push] checks this before calling. */
    public suspend fun autoRotate(room: ByteArray): PushOutcome {
        val state = replayMembershipState(room)
        val newEpoch = state.epoch + 1
        val newKey = crypto.randomBytes(32)
        val userBoxKeys = collectUserBoxKeys(room)
        val nonPending = state.members().filter { it.role != Role.PENDING }

        val wraps = nonPending.mapNotNull { member ->
            val userBox = userBoxKeys[member.user.toKey()] ?: return@mapNotNull null
            val sealed = EpochKeys.seal(crypto, userBox, room, newEpoch, newKey)
            CborValue.Map(mapOf(0L to CborValue.Bytes(member.user), 1L to CborValue.Bytes(sealed)))
        }
        if (wraps.size != nonPending.size) {
            return PushOutcome.Error(500, "invalid", "missing a userBoxKey for a current member - cannot build epochRotate")
        }

        val body = CborValue.Map(mapOf(0L to CborValue.UInt(newEpoch), 1L to CborValue.Array(wraps)))
        val outcome = appendLogEntry(room) { index, prev ->
            LogEntry.sign(crypto, device.secretKey, room, index, prev, userIdentity.userKey, deviceCert, EntryType.EPOCH_ROTATE, body, nowUnixSeconds())
        }
        if (outcome != PushOutcome.Ok) return outcome

        registerEpochKey(room, newEpoch, newKey)
        reuploadEnvelopesAfterRotation(room, newEpoch, newKey)
        return PushOutcome.Ok
    }

    /** §3.5: re-seals every locally-known invite secret under [newEpoch]/[newKey] and PUTs the
     * refreshed envelope. Silently skips invites this device never created (no secret stored) or
     * that are no longer active (revoked/not an open invite) - another admin device, or this
     * device on a later pull, will have its own chance. */
    private suspend fun reuploadEnvelopesAfterRotation(room: ByteArray, newEpoch: Long, newKey: ByteArray) {
        val activeOpenInviteIds = replayMembershipState(room).invites()
            .filter { !it.revoked && !it.requiresApproval }
            .map { it.id.toKey() }
            .toSet()
        for (row in store.inviteSecretsFor(room)) {
            if (row.invite_id.toKey() !in activeOpenInviteIds) continue
            val envelope = InviteEnvelope.seal(crypto, row.secret, room, row.invite_id, newEpoch, newKey)
            authedRequest(HttpMethod.Put, path("/invites/${b64Url(room)}/${b64Url(row.invite_id)}/envelope"), envelope)
        }
    }

    /** Authors an `inviteCreate` entry and, for open (no-approval) invites, mints a fresh
     * [org.squaddle.core.membership.InviteEnvelope] and uploads it - the join flow's other half,
     * [joinViaLink]. The secret is persisted locally (§3.5's re-upload-after-rotation needs it
     * later; nothing else can ever recover it). */
    public suspend fun createInvite(
        room: ByteArray,
        inviteId: ByteArray,
        requiresApproval: Boolean,
        expiresAt: Long? = null,
        maxUses: Int? = null,
        roomName: String? = null,
    ): PushOutcome {
        val body = CborValue.Map(
            buildMap {
                put(0L, CborValue.Bytes(inviteId))
                expiresAt?.let { put(1L, CborValue.UInt(it)) }
                maxUses?.let { put(2L, CborValue.UInt(it.toLong())) }
                put(3L, CborValue.Bool(requiresApproval))
                put(4L, CborValue.Text("member"))
            },
        )
        val outcome = appendLogEntry(room) { index, prev ->
            LogEntry.sign(crypto, device.secretKey, room, index, prev, userIdentity.userKey, deviceCert, EntryType.INVITE_CREATE, body, nowUnixSeconds())
        }
        if (outcome != PushOutcome.Ok || requiresApproval) return outcome

        val epoch = replayMembershipState(room).epoch
        val key = epochKeyFor(room, epoch) ?: return PushOutcome.Error(500, "invalid", "epoch key not available to seal the invite envelope")
        val secret = crypto.randomBytes(32)
        store.insertInviteSecret(room, inviteId, secret)
        val envelope = InviteEnvelope.seal(crypto, secret, room, inviteId, epoch, key, roomName)
        val resp = authedRequest(HttpMethod.Put, path("/invites/${b64Url(room)}/${b64Url(inviteId)}/envelope"), envelope)
        if (resp.status != HttpStatusCode.NoContent && resp.status != HttpStatusCode.OK) {
            val err = parseError(resp.bodyAsBytes())
            return PushOutcome.Error(resp.status.value, err?.code ?: "invalid", err?.message ?: "envelope upload failed")
        }
        return PushOutcome.Ok
    }

    /** Registers this device's own [deviceCert] with the relay (`PUT /users/{u}/devices/{d}`) -
     * needed before anyone else can resolve "does this device belong to this author" for this
     * device's future log entries/ops (§2.2/§4.1's documented relay-side limitation). Unlike
     * every other write, this request is self-certifying even for a device the relay has never
     * seen (same as request-auth itself), so it's always safe to call first. */
    public suspend fun publishDeviceCert(): PushOutcome {
        val body = CanonicalCborCodec.encode(deviceCert.toFullCbor())
        val resp = authedRequest(HttpMethod.Put, path("/users/${b64Url(userIdentity.userKey)}/devices/${b64Url(device.publicKey)}"), body)
        if (resp.status != HttpStatusCode.NoContent) {
            val err = parseError(resp.bodyAsBytes())
            return PushOutcome.Error(resp.status.value, err?.code ?: "invalid", err?.message ?: "device cert publish failed")
        }
        return PushOutcome.Ok
    }

    /** Fetches and opens an invite envelope (unauthenticated GET, per §3.5/relay-api.yaml), pulls
     * the room's current log only (a brand-new joiner has no local history yet and must learn
     * the real chain head before it can sign a `join` entry against the correct index/prev -
     * [pullLog], not the full [pull]: `getOps` is members-only and this joiner isn't one yet),
     * then authors+pushes the `join` entry. [inviteSecret] is the bytes from the invite link's
     * URL fragment - never logged, never sent anywhere itself (only used locally to derive
     * `inviteKey` and decrypt). */
    public suspend fun joinViaLink(room: ByteArray, inviteId: ByteArray, inviteSecret: ByteArray): PushOutcome {
        val resp = httpClient.request("$httpScheme://$relayHost${path("/invites/${b64Url(room)}/${b64Url(inviteId)}/envelope")}") {
            this.method = HttpMethod.Get
        }
        if (resp.status != HttpStatusCode.OK) {
            val err = parseError(resp.bodyAsBytes())
            return PushOutcome.Error(resp.status.value, err?.code ?: "invalid", err?.message ?: "envelope fetch failed")
        }
        val content = InviteEnvelope.open(crypto, inviteSecret, room, inviteId, resp.bodyAsBytes())
            ?: return PushOutcome.Error(resp.status.value, "invalid", "envelope did not decrypt")
        registerEpochKey(room, content.epoch, content.epochKey)

        val pullOutcome = pullLog(room) // not the full pull(): getOps is members-only and this joiner isn't one yet
        if (pullOutcome is SyncOutcome.Error) return PushOutcome.Error(pullOutcome.status, pullOutcome.code, pullOutcome.message)

        val body = CborValue.Map(mapOf(0L to CborValue.Bytes(inviteId)))
        return appendLogEntry(room) { index, prev ->
            LogEntry.sign(crypto, device.secretKey, room, index, prev, userIdentity.userKey, deviceCert, EntryType.JOIN, body, nowUnixSeconds())
        }
    }

    /**
     * PROTOCOL.md §6: opens `/ws`, subscribes to [rooms], and calls [pull] on every push - a
     * fresh [pull] naturally covers both log and ops regardless of which one [WsEvent.k] names
     * (simpler than threading a "just this stream" fast path through pull() for an optimization
     * the spec doesn't require). Suspends for as long as the connection stays open; returns
     * normally on a clean server close, rethrows anything else (incl. cancellation, so a caller's
     * coroutine scope can actually stop this). Callers wanting automatic reconnect should wrap
     * this in their own retry loop - that policy is deliberately not baked in here.
     */
    public suspend fun connectLiveUpdates(rooms: List<ByteArray>) {
        if (rooms.isEmpty()) return
        val roomRefs = rooms.associateBy { Base32.encode(it) }
        val ts = nowUnixSeconds()
        val authHeader = RequestAuth.headerValue(crypto, device.secretKey, device.publicKey, "GET", path("/ws"), ts, crypto.randomBytes(16), ByteArray(0))

        httpClient.webSocket("$wsScheme://$relayHost${path("/ws")}", request = { header("Authorization", authHeader) }) {
            send(Frame.Text(Json.encodeToString(WsSubscribe.serializer(), WsSubscribe(roomRefs.keys.toList()))))
            for (frame in incoming) {
                if (frame !is Frame.Text) continue
                val event = try {
                    Json.decodeFromString(WsEvent.serializer(), frame.data.decodeToString())
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    continue
                }
                val room = roomRefs[event.r] ?: continue
                pull(room)
            }
        }
    }
}
