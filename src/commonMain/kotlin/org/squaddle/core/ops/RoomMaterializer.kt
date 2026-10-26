package org.squaddle.core.ops

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.encoding.Hex
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipState
import org.squaddle.core.membership.MembershipStateImpl
import org.squaddle.core.membership.StoredEntry
import org.squaddle.core.store.LocalStore
import org.squaddle.core.sync.SyncClient

private fun ByteArray.toKey(): String = Hex.encode(this)

/** Replays [room]'s local log into (membership history, a cert-by-device lookup) - the two
 * ingredients any op-materializer needs before it can authorize/open ops. Pure local replay, no
 * network - mirrors what `core/cli`'s `materializeRoomState`/android's `RealSyncGateway.
 * buildHistory`+`certResolverFromLog` each already built by hand, identically; factored out here
 * as a third call site (webclient's jsapi) needs the exact same thing. */
public fun replayMembershipHistory(crypto: Crypto, store: LocalStore, room: ByteArray): Pair<MembershipHistory, (ByteArray) -> DeviceCert?> {
    var state: MembershipState = MembershipStateImpl.empty(crypto)
    val storedEntries = mutableListOf<StoredEntry>()
    val byDevice = mutableMapOf<String, DeviceCert>()
    for (row in store.logEntriesFrom(room, 0L)) {
        val entry = LogEntry.decode(row.entry_cbor) ?: continue
        val stored = StoredEntry(entry, row.rts)
        state = state.apply(stored).getOrElse { state }
        storedEntries += stored
        byDevice[entry.cert.device.toKey()] = entry.cert
    }
    val history = MembershipHistory.build(storedEntries, MembershipStateImpl.empty(crypto))
    return history to { device: ByteArray -> byDevice[device.toKey()] }
}

/** Decrypts+opens every locally-stored (already-pulled) op for [room] and folds the result into
 * a [RoomState] - no network (callers needing fresh data should [SyncClient.pull] first). Safe
 * for any of core's callers to share verbatim; see [replayMembershipHistory]'s doc comment. */
public suspend fun materializeRoomState(crypto: Crypto, sync: SyncClient, store: LocalStore, room: ByteArray): RoomState {
    sync.rehydrateEpochKeys(room)
    val (history, certOf) = replayMembershipHistory(crypto, store, room)
    val ops = store.opsAfter(room, 0L).mapNotNull { row ->
        val env = OpEnvelope.decode(row.envelope_cbor) ?: return@mapNotNull null
        val key = sync.epochKeyFor(room, env.epoch) ?: return@mapNotNull null
        val opened = env.open(crypto, key, certOf)
        (opened as? OpOpenResult.Ok)?.let { env to it.body }
    }
    return RoomState.fold(ops, history)
}
