package org.squaddle.core.store

import app.cash.sqldelight.db.SqlDriver

/** `name` is a file path on JVM, a filename handed to Android's own app-data resolution on
 * Android - see the platform `actual`s. Pass `":memory:"`-equivalent per-platform convention for
 * tests (JVM: an actual `":memory:"` path works via the JDBC sqlite driver). */
public expect fun createSqlDriver(name: String): SqlDriver

/**
 * Thin wrapper over the generated [SquaddleDb] queries - no business logic here (that stays in
 * [org.squaddle.core.ops.RoomState] / the sync client); this layer is pure persistence, mirroring
 * exactly what the relay itself stores (PROTOCOL.md §3/§4) plus the purely-local `cursors`/
 * `outbox` bookkeeping a sync client needs that the relay has no concept of.
 */
public class LocalStore(driver: SqlDriver) {
    private val db: SquaddleDb = SquaddleDb(driver)
    private val q = db.squaddleQueries

    public fun insertLogEntry(room: ByteArray, idx: Long, entryCbor: ByteArray, rts: Long) {
        q.insertLogEntry(room, idx, entryCbor, rts)
    }

    public fun logEntriesFrom(room: ByteArray, fromIdx: Long): List<Log_entries> =
        q.logEntriesFrom(room, fromIdx).executeAsList()

    public fun maxLogIndex(room: ByteArray): Long? = q.maxLogIndex(room).executeAsOne().MAX

    public fun insertOp(room: ByteArray, cursor: Long, opId: ByteArray, device: ByteArray, seq: Long, envelopeCbor: ByteArray) {
        q.insertOp(room, cursor, opId, device, seq, envelopeCbor)
    }

    public fun opsAfter(room: ByteArray, afterCursor: Long): List<Ops> =
        q.opsAfter(room, afterCursor).executeAsList()

    public fun maxOpsCursor(room: ByteArray): Long? = q.maxOpsCursor(room).executeAsOne().MAX

    public fun upsertCursor(room: ByteArray, lastLogIndex: Long, lastOpsCursor: Long) {
        q.upsertCursor(room, lastLogIndex, lastOpsCursor)
    }

    public fun cursorFor(room: ByteArray): Cursors? = q.cursorFor(room).executeAsOneOrNull()

    public fun upsertDeviceSeq(room: ByteArray, device: ByteArray, seq: Long) {
        q.upsertDeviceSeq(room, device, seq)
    }

    public fun deviceSeqsFor(room: ByteArray): List<Device_seq> = q.deviceSeqsFor(room).executeAsList()

    public fun insertOutbox(
        room: ByteArray,
        localOrder: Long,
        epoch: Long,
        seq: Long,
        lamport: Long,
        nonce: ByteArray,
        bodyCbor: ByteArray,
        envelopeCbor: ByteArray,
    ) {
        q.insertOutbox(room, localOrder, epoch, seq, lamport, nonce, bodyCbor, envelopeCbor)
    }

    /** Re-encryption in place (PROTOCOL.md §3.4 stale_epoch retry): [epoch]/[nonce]/[envelopeCbor]
     * change, [bodyCbor]/[seq]/[lamport] never do - the op's identity and plaintext content don't
     * change just because it's being sealed under a newer epoch key. */
    public fun replaceOutboxEnvelope(room: ByteArray, localOrder: Long, epoch: Long, nonce: ByteArray, envelopeCbor: ByteArray) {
        q.replaceOutboxEnvelope(epoch, nonce, envelopeCbor, room, localOrder)
    }

    public fun outboxFor(room: ByteArray): List<Outbox> = q.outboxFor(room).executeAsList()

    public fun deleteOutboxEntry(room: ByteArray, localOrder: Long) {
        q.deleteOutboxEntry(room, localOrder)
    }

    public fun maxOutboxLocalOrder(room: ByteArray): Long? = q.maxOutboxLocalOrder(room).executeAsOne().MAX

    public fun insertInviteSecret(room: ByteArray, inviteId: ByteArray, secret: ByteArray) {
        q.insertInviteSecret(room, inviteId, secret)
    }

    public fun inviteSecretsFor(room: ByteArray): List<Invite_secrets> = q.inviteSecretsFor(room).executeAsList()

    public fun deleteInviteSecret(room: ByteArray, inviteId: ByteArray) {
        q.deleteInviteSecret(room, inviteId)
    }

    public fun insertEpochKey(room: ByteArray, epoch: Long, key: ByteArray) {
        q.insertEpochKey(room, epoch, key)
    }

    public fun epochKeyRowFor(room: ByteArray, epoch: Long): Epoch_keys? = q.epochKeyRowFor(room, epoch).executeAsOneOrNull()
}
