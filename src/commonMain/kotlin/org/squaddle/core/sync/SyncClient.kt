package org.squaddle.core.sync

/** PROTOCOL.md §5 + relay-api.yaml. TODO(M3): Ktor implementation with outbox + retry on stale_head/stale_epoch. */
public interface SyncClient {
    public suspend fun pullLog(roomRef: String, fromIndex: Long)
    public suspend fun pullOps(roomRef: String, afterCursor: Long)
    public suspend fun flushOutbox(roomRef: String)
}
