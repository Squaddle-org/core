package org.squaddle.core.ops

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.encoding.Hex

/**
 * PROTOCOL.md §4.4 names a Snapshot's `ct` plaintext as "materialized state + seq vector" without
 * a numbered field table (unlike every other structure in the spec, which gets one precisely so
 * every implementation agrees on the wire bytes) - this inner blob is opaque to everyone except
 * the client that wrote it (the relay never decrypts it, and no other implementation exists yet
 * to disagree with), so there is nothing cross-implementation to settle and no spec PR is needed.
 * This file is simply *a* reasonable, internally-documented choice: a direct CBOR encoding of
 * [RoomState] (itself already a [LwwStamp]-per-field structure, so ties still resolve correctly
 * for any op applied after a snapshot is loaded) plus the per-device `seq` map §4.1 calls the
 * "seq vector".
 *
 * Top-level map: `{0:ideas[], 1:comments[], 2:events[], 3:votes[], 4:rsvps[], 5:profiles[],
 * 6:deviceSeq{deviceKey->seq}}`. Every [LwwStamp] is encoded as `[lamport, deviceKey]`.
 */
public data class SnapshotPayload(val state: RoomState, val deviceSeq: Map<String, Long>)

/** [RoomState]'s "never written" sentinel stamp (`lamport = Long.MIN_VALUE`, `device` empty) -
 * never a real stamp (§4.1's lamport is always `max(seen)+1`, positive), so it's encoded as a
 * dedicated `null` rather than pushed through the integer codec (which can't represent
 * `Long.MIN_VALUE` as a signed CBOR argument without overflowing). */
private fun LwwStamp.toCbor(): CborValue =
    if (device.isEmpty()) CborValue.Null else CborValue.Array(listOf(CborValue.UInt(lamport), CborValue.Bytes(device)))

private fun CborValue.toLwwStamp(): LwwStamp = when (this) {
    is CborValue.Null -> LwwStamp(Long.MIN_VALUE, ByteArray(0))
    is CborValue.Array -> LwwStamp((items[0] as CborValue.UInt).value, (items[1] as CborValue.Bytes).value)
    else -> throw CborFormatException("expected a LwwStamp (array or null)")
}

private fun String?.toCbor(): CborValue = this?.let { CborValue.Text(it) } ?: CborValue.Null
private fun CborValue.toTextOrNull(): String? = (this as? CborValue.Text)?.value

private fun Idea.toCbor(): CborValue = CborValue.Map(
    mapOf(
        0L to CborValue.Bytes(id), 1L to CborValue.Bytes(createdBy),
        2L to CborValue.Text(title), 3L to titleStamp.toCbor(),
        4L to desc.toCbor(), 5L to descStamp.toCbor(),
        6L to CborValue.Array(tags.map { CborValue.Text(it) }), 7L to tagsStamp.toCbor(),
        8L to status.toCbor(), 9L to statusStamp.toCbor(),
        10L to CborValue.Bool(deleted), 11L to deletedStamp.toCbor(),
    ),
)

private fun CborValue.toIdea(): Idea {
    val m = (this as CborValue.Map).entries
    return Idea(
        id = (m.getValue(0L) as CborValue.Bytes).value,
        createdBy = (m.getValue(1L) as CborValue.Bytes).value,
        title = (m.getValue(2L) as CborValue.Text).value, titleStamp = m.getValue(3L).toLwwStamp(),
        desc = m.getValue(4L).toTextOrNull(), descStamp = m.getValue(5L).toLwwStamp(),
        tags = (m.getValue(6L) as CborValue.Array).items.map { (it as CborValue.Text).value }, tagsStamp = m.getValue(7L).toLwwStamp(),
        status = m.getValue(8L).toTextOrNull(), statusStamp = m.getValue(9L).toLwwStamp(),
        deleted = (m.getValue(10L) as CborValue.Bool).value, deletedStamp = m.getValue(11L).toLwwStamp(),
    )
}

private fun Comment.toCbor(): CborValue = CborValue.Map(
    mapOf(
        0L to CborValue.Bytes(id), 1L to CborValue.Bytes(ideaId), 2L to CborValue.Bytes(author),
        3L to CborValue.Text(text), 4L to CborValue.Bool(deleted), 5L to deletedStamp.toCbor(),
    ),
)

private fun CborValue.toComment(): Comment {
    val m = (this as CborValue.Map).entries
    return Comment(
        id = (m.getValue(0L) as CborValue.Bytes).value, ideaId = (m.getValue(1L) as CborValue.Bytes).value,
        author = (m.getValue(2L) as CborValue.Bytes).value, text = (m.getValue(3L) as CborValue.Text).value,
        deleted = (m.getValue(4L) as CborValue.Bool).value, deletedStamp = m.getValue(5L).toLwwStamp(),
    )
}

private fun Event.toCbor(): CborValue = CborValue.Map(
    mapOf(
        0L to CborValue.Bytes(id), 1L to CborValue.Bytes(createdBy),
        2L to (ideaId?.let { CborValue.Bytes(it) } ?: CborValue.Null),
        3L to CborValue.Text(title), 4L to titleStamp.toCbor(),
        5L to CborValue.UInt(start), 6L to startStamp.toCbor(),
        7L to (end?.let { CborValue.UInt(it) } ?: CborValue.Null), 8L to endStamp.toCbor(),
        9L to CborValue.Text(tz), 10L to tzStamp.toCbor(),
        11L to location.toCbor(), 12L to locationStamp.toCbor(),
        13L to CborValue.Bool(allDay), 14L to allDayStamp.toCbor(),
        15L to CborValue.Bool(cancelled), 16L to cancelledStamp.toCbor(),
    ),
)

private fun CborValue.toEvent(): Event {
    val m = (this as CborValue.Map).entries
    return Event(
        id = (m.getValue(0L) as CborValue.Bytes).value, createdBy = (m.getValue(1L) as CborValue.Bytes).value,
        ideaId = (m[2L] as? CborValue.Bytes)?.value,
        title = (m.getValue(3L) as CborValue.Text).value, titleStamp = m.getValue(4L).toLwwStamp(),
        start = (m.getValue(5L) as CborValue.UInt).value, startStamp = m.getValue(6L).toLwwStamp(),
        end = (m[7L] as? CborValue.UInt)?.value, endStamp = m.getValue(8L).toLwwStamp(),
        tz = (m.getValue(9L) as CborValue.Text).value, tzStamp = m.getValue(10L).toLwwStamp(),
        location = m.getValue(11L).toTextOrNull(), locationStamp = m.getValue(12L).toLwwStamp(),
        allDay = (m.getValue(13L) as CborValue.Bool).value, allDayStamp = m.getValue(14L).toLwwStamp(),
        cancelled = (m.getValue(15L) as CborValue.Bool).value, cancelledStamp = m.getValue(16L).toLwwStamp(),
    )
}

private fun Map.Entry<String, Vote>.voteEntryToCbor(): CborValue = CborValue.Map(
    mapOf(0L to CborValue.Text(key), 1L to value.value.toCborInt(), 2L to value.stamp.toCbor()),
)
private fun Int.toCborInt(): CborValue = if (this < 0) CborValue.NInt(toLong()) else CborValue.UInt(toLong())
private fun CborValue.toIntValue(): Int = when (this) {
    is CborValue.UInt -> value.toInt()
    is CborValue.NInt -> value.toInt()
    else -> throw CborFormatException("expected an integer")
}
private fun CborValue.toVoteEntry(): Pair<String, Vote> {
    val m = (this as CborValue.Map).entries
    return (m.getValue(0L) as CborValue.Text).value to Vote(m.getValue(1L).toIntValue(), m.getValue(2L).toLwwStamp())
}

private fun Map.Entry<String, Rsvp>.rsvpEntryToCbor(): CborValue = CborValue.Map(
    mapOf(0L to CborValue.Text(key), 1L to CborValue.Text(value.value), 2L to value.stamp.toCbor()),
)
private fun CborValue.toRsvpEntry(): Pair<String, Rsvp> {
    val m = (this as CborValue.Map).entries
    return (m.getValue(0L) as CborValue.Text).value to Rsvp((m.getValue(1L) as CborValue.Text).value, m.getValue(2L).toLwwStamp())
}

private fun Map.Entry<String, Profile>.profileEntryToCbor(): CborValue = CborValue.Map(
    mapOf(0L to CborValue.Text(key), 1L to CborValue.Text(value.displayName), 2L to value.emoji.toCbor(), 3L to value.stamp.toCbor()),
)
private fun CborValue.toProfileEntry(): Pair<String, Profile> {
    val m = (this as CborValue.Map).entries
    return (m.getValue(0L) as CborValue.Text).value to Profile((m.getValue(1L) as CborValue.Text).value, m.getValue(2L).toTextOrNull(), m.getValue(3L).toLwwStamp())
}

private fun SnapshotPayload.toCbor(): CborValue = CborValue.Map(
    mapOf(
        0L to CborValue.Array(state.ideas.values.map { it.toCbor() }),
        1L to CborValue.Array(state.comments.values.map { it.toCbor() }),
        2L to CborValue.Array(state.events.values.map { it.toCbor() }),
        3L to CborValue.Array(state.votes.entries.map { it.voteEntryToCbor() }),
        4L to CborValue.Array(state.rsvps.entries.map { it.rsvpEntryToCbor() }),
        5L to CborValue.Array(state.profiles.entries.map { it.profileEntryToCbor() }),
        6L to CborValue.Array(deviceSeq.entries.map { (k, v) -> CborValue.Map(mapOf(0L to CborValue.Text(k), 1L to CborValue.UInt(v))) }),
    ),
)

/** Encodes [this] to the canonical CBOR plaintext a [Snapshot]'s `ct` encrypts. */
public fun SnapshotPayload.encode(): ByteArray = CanonicalCborCodec.encode(toCbor())

/** `null` on malformed CBOR - never throws. */
public fun decodeSnapshotPayload(bytes: ByteArray): SnapshotPayload? {
    val top = try {
        (CanonicalCborCodec.decode(bytes) as? CborValue.Map)?.entries ?: return null
    } catch (e: CborFormatException) {
        return null
    }
    return try {
        val ideas = (top.getValue(0L) as CborValue.Array).items.map { it.toIdea() }.associateBy { it.id.toSnapshotKey() }
        val comments = (top.getValue(1L) as CborValue.Array).items.map { it.toComment() }.associateBy { it.id.toSnapshotKey() }
        val events = (top.getValue(2L) as CborValue.Array).items.map { it.toEvent() }.associateBy { it.id.toSnapshotKey() }
        val votes = (top.getValue(3L) as CborValue.Array).items.associate { it.toVoteEntry() }
        val rsvps = (top.getValue(4L) as CborValue.Array).items.associate { it.toRsvpEntry() }
        val profiles = (top.getValue(5L) as CborValue.Array).items.associate { it.toProfileEntry() }
        val deviceSeq = (top.getValue(6L) as CborValue.Array).items.associate {
            val m = (it as CborValue.Map).entries
            (m.getValue(0L) as CborValue.Text).value to (m.getValue(1L) as CborValue.UInt).value
        }
        SnapshotPayload(RoomState(ideas, comments, events, votes, rsvps, profiles), deviceSeq)
    } catch (e: NoSuchElementException) {
        null
    } catch (e: ClassCastException) {
        null
    } catch (e: CborFormatException) {
        null
    }
}

private fun ByteArray.toSnapshotKey(): String = Hex.encode(this)

/** Encrypts [payload] under [epochKey] and signs the result - the client-side half of §4.4's
 * "relay never decrypts ct"; the relay only ever sees the already-sealed [Snapshot]. */
public fun createSnapshot(
    crypto: Crypto,
    deviceSecretKey: ByteArray,
    epochKey: ByteArray,
    room: ByteArray,
    epoch: Long,
    coversUpTo: Long,
    author: ByteArray,
    device: ByteArray,
    payload: SnapshotPayload,
    nonce: ByteArray = crypto.randomBytes(24),
): Snapshot {
    val withoutCt = Snapshot(v = 1, room = room, epoch = epoch, coversUpTo = coversUpTo, nonce = nonce, ct = ByteArray(0), author = author, device = device)
    val ad = CanonicalCborCodec.encode(withoutCt.toAdCbor())
    val ct = crypto.aeadEncrypt(epochKey, nonce, payload.encode(), ad)
    return Snapshot.sign(crypto, deviceSecretKey, room, epoch, coversUpTo, nonce, ct, author, device)
}

/** `null` if [snapshot] doesn't verify, doesn't decrypt under [epochKey], or its plaintext isn't
 * a well-formed [SnapshotPayload] - never throws. */
public fun applySnapshot(crypto: Crypto, snapshot: Snapshot, epochKey: ByteArray): SnapshotPayload? {
    if (!snapshot.verify(crypto)) return null
    val ad = CanonicalCborCodec.encode(snapshot.toAdCbor())
    val plaintext = crypto.aeadDecrypt(epochKey, snapshot.nonce, snapshot.ct, ad) ?: return null
    return decodeSnapshotPayload(plaintext)
}
