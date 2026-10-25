@file:OptIn(ExperimentalEncodingApi::class)

package org.squaddle.core.sync

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.EpochKeys
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipState
import org.squaddle.core.membership.MembershipStateImpl
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
) {
    // room.toKey() -> epoch -> epochKey. In-memory only - PROTOCOL.md never asks a client to
    // persist epoch keys at rest beyond what EpochKeys.open can re-derive from the log itself, so
    // a process restart just re-unwraps them from the already-pulled log on the next full replay.
    private val epochKeys = mutableMapOf<String, MutableMap<Long, ByteArray>>()

    public fun registerEpochKey(room: ByteArray, epoch: Long, key: ByteArray) {
        epochKeys.getOrPut(room.toKey()) { mutableMapOf() }[epoch] = key
    }

    public fun epochKeyFor(room: ByteArray, epoch: Long): ByteArray? = epochKeys[room.toKey()]?.get(epoch)

    private fun b64Url(bytes: ByteArray): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)

    private fun path(suffix: String): String = "/v1$suffix"

    private suspend fun authedRequest(method: HttpMethod, pathAndQuery: String, body: ByteArray = ByteArray(0)): HttpResponse {
        val ts = nowUnixSeconds()
        val header = RequestAuth.headerValue(crypto, device.secretKey, device.publicKey, method.value, pathAndQuery, ts, body)
        return httpClient.request("https://$relayHost$pathAndQuery") {
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
        val existingCursor = store.cursorFor(room)
        val fromIndex = (existingCursor?.last_log_index ?: -1L) + 1
        val afterCursor = existingCursor?.last_ops_cursor ?: 0L

        val logResp = authedRequest(HttpMethod.Get, path("/rooms/${b64Url(room)}/log?from=$fromIndex"))
        if (logResp.status != HttpStatusCode.OK) return errorOutcome(logResp)
        var lastLogIndex = existingCursor?.last_log_index ?: -1L
        for ((entryCbor, rts) in decodeLogResponse(logResp.bodyAsBytes())) {
            val entry = LogEntry.decode(entryCbor) ?: continue
            store.insertLogEntry(room, entry.index, entryCbor, rts)
            if (entry.index > lastLogIndex) lastLogIndex = entry.index
            observeEpochWraps(room, entry)
        }

        val opsResp = authedRequest(HttpMethod.Get, path("/rooms/${b64Url(room)}/ops?after=$afterCursor"))
        if (opsResp.status != HttpStatusCode.OK) return errorOutcome(opsResp)
        val (ops, next) = decodeOpsResponse(opsResp.bodyAsBytes())
        for ((opCursor, envelopeCbor) in ops) {
            val env = OpEnvelope.decode(envelopeCbor) ?: continue
            store.insertOp(room, opCursor, env.opId(crypto), env.device, env.seq, envelopeCbor)
            store.upsertDeviceSeq(room, env.device, env.seq)
        }

        store.upsertCursor(room, lastLogIndex, next)
        return SyncOutcome.Ok
    }

    private suspend fun errorOutcome(resp: HttpResponse): SyncOutcome.Error {
        val err = parseError(resp.bodyAsBytes())
        return SyncOutcome.Error(resp.status.value, err?.code ?: "invalid", err?.message ?: "unparseable error body")
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

    /** Pushes every outstanding outbox op for [room] as one batch. On `409 stale_epoch`:
     * re-encrypts the outbox under the new epoch key (unwrapped via a fresh [pull]) and retries
     * once. `rotation_required` handling (auto-rotate for admin/owner, wait otherwise) is a
     * separate concern layered on top of this - see the room-session helpers. */
    public suspend fun push(room: ByteArray, allowStaleEpochRetry: Boolean = true): PushOutcome {
        val pending = store.outboxFor(room)
        if (pending.isEmpty()) return PushOutcome.Ok

        val batch = CanonicalCborCodec.encode(CborValue.Array(pending.map { CanonicalCborCodec.decode(it.envelope_cbor) }))
        val resp = authedRequest(HttpMethod.Post, path("/rooms/${b64Url(room)}/ops"), batch)
        if (resp.status == HttpStatusCode.Created) {
            for (entry in pending) store.deleteOutboxEntry(room, entry.local_order)
            return PushOutcome.Ok
        }

        val err = parseError(resp.bodyAsBytes()) ?: return PushOutcome.Error(resp.status.value, "invalid", "unparseable error body")
        if (err.code == "stale_epoch" && allowStaleEpochRetry) {
            pull(room) // picks up the epochRotate entry and unwraps the new key
            if (reencryptOutboxForNewEpoch(room)) return push(room, allowStaleEpochRetry = false)
        }
        return PushOutcome.Error(resp.status.value, err.code, err.message)
    }
}
