package org.squaddle.core.ops

/** PROTOCOL.md §4. */
public data class OpEnvelope(
    val v: Int = 1,
    val room: ByteArray,
    val epoch: Long,
    val author: ByteArray,
    val device: ByteArray,
    val seq: Long,
    val lamport: Long,
    val nonce: ByteArray,
    val ct: ByteArray,
    val sig: ByteArray?,
) { public companion object { public const val DOMAIN: String = "op" } }

public sealed interface OpBody {
    public data class IdeaCreate(val id: ByteArray, val title: String, val desc: String?, val tags: List<String>) : OpBody
    public data class IdeaSet(val id: ByteArray, val field: String, val value: Any?) : OpBody
    public data class IdeaDelete(val id: ByteArray) : OpBody
    public data class VoteSet(val ideaId: ByteArray, val value: Int) : OpBody
    public data class CommentAdd(val id: ByteArray, val ideaId: ByteArray, val text: String) : OpBody
    public data class CommentDelete(val id: ByteArray) : OpBody
    public data class EventCreate(
        val id: ByteArray, val ideaId: ByteArray?, val title: String,
        val start: Long, val end: Long?, val tz: String, val location: String?, val allDay: Boolean,
    ) : OpBody
    public data class EventSet(val id: ByteArray, val field: String, val value: Any?) : OpBody
    public data class EventCancel(val id: ByteArray) : OpBody
    public data class RsvpSet(val eventId: ByteArray, val value: String) : OpBody
    public data class ProfileSet(val displayName: String, val emoji: String?) : OpBody
    /** Forward compatibility: unknown types are kept but ignored by the materializer. */
    public data class Unknown(val type: String) : OpBody
}

/** LWW ordering key: (lamport, deviceKey bytes) lexicographic. */
public data class LwwStamp(val lamport: Long, val device: ByteArray) : Comparable<LwwStamp> {
    override fun compareTo(other: LwwStamp): Int {
        if (lamport != other.lamport) return lamport.compareTo(other.lamport)
        for (i in 0 until minOf(device.size, other.device.size)) {
            val c = (device[i].toInt() and 0xff).compareTo(other.device[i].toInt() and 0xff)
            if (c != 0) return c
        }
        return device.size.compareTo(other.device.size)
    }
}
// TODO(M3): RoomState materializer (fold over verified, decrypted ops + MembershipState for authorization)
