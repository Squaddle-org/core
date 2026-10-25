package org.squaddle.core.ops

import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue

/**
 * PROTOCOL.md §4.2: `OpBody { 0: type tstr, 1: payload map }`. The `type` strings are the exact
 * literals from §4.2's table - cross-implementation relevant, since every client must agree on
 * them to interoperate. The inner payload *field numbering* is not spec'd (§4.2 only gives an
 * informal shape per type, no numbered table like §3.3/§4.1) - same category as [Snapshot]'s
 * inner materialized-state format: this is the one and only (currently) implementation, so there
 * is nothing to disagree with; numbered here for compactness, documented so a future platform
 * port has something concrete to match.
 */
private fun OpBody.typeName(): String = when (this) {
    is OpBody.IdeaCreate -> "idea.create"
    is OpBody.IdeaSet -> "idea.set"
    is OpBody.IdeaDelete -> "idea.delete"
    is OpBody.VoteSet -> "vote.set"
    is OpBody.CommentAdd -> "comment.add"
    is OpBody.CommentDelete -> "comment.delete"
    is OpBody.EventCreate -> "event.create"
    is OpBody.EventSet -> "event.set"
    is OpBody.EventCancel -> "event.cancel"
    is OpBody.RsvpSet -> "rsvp.set"
    is OpBody.ProfileSet -> "profile.set"
    is OpBody.Unknown -> type
}

/** `idea.set`/`event.set`'s polymorphic `value`: a field's own text, a tag list, or absent (clears it). */
private fun Any?.toValueCbor(): CborValue = when (this) {
    null -> CborValue.Null
    is String -> CborValue.Text(this)
    is List<*> -> CborValue.Array(map { CborValue.Text(it.toString()) })
    else -> throw IllegalArgumentException("unsupported idea.set/event.set value: $this")
}

private fun CborValue.fromValueCbor(): Any? = when (this) {
    is CborValue.Null -> null
    is CborValue.Text -> value
    is CborValue.Array -> items.map { (it as CborValue.Text).value }
    else -> throw CborFormatException("unsupported idea.set/event.set value shape")
}

private fun Int.toCborInt(): CborValue = if (this < 0) CborValue.NInt(toLong()) else CborValue.UInt(toLong())
private fun CborValue.toInt(): Int = when (this) {
    is CborValue.UInt -> value.toInt()
    is CborValue.NInt -> value.toInt()
    else -> throw CborFormatException("expected an integer")
}

private fun OpBody.payloadCbor(): CborValue.Map {
    val m = linkedMapOf<Long, CborValue>()
    when (this) {
        is OpBody.IdeaCreate -> {
            m[0L] = CborValue.Bytes(id)
            m[1L] = CborValue.Text(title)
            desc?.let { m[2L] = CborValue.Text(it) }
            m[3L] = CborValue.Array(tags.map { CborValue.Text(it) })
        }
        is OpBody.IdeaSet -> {
            m[0L] = CborValue.Bytes(id)
            m[1L] = CborValue.Text(field)
            m[2L] = value.toValueCbor()
        }
        is OpBody.IdeaDelete -> m[0L] = CborValue.Bytes(id)
        is OpBody.VoteSet -> {
            m[0L] = CborValue.Bytes(ideaId)
            m[1L] = value.toCborInt()
        }
        is OpBody.CommentAdd -> {
            m[0L] = CborValue.Bytes(id)
            m[1L] = CborValue.Bytes(ideaId)
            m[2L] = CborValue.Text(text)
        }
        is OpBody.CommentDelete -> m[0L] = CborValue.Bytes(id)
        is OpBody.EventCreate -> {
            m[0L] = CborValue.Bytes(id)
            ideaId?.let { m[1L] = CborValue.Bytes(it) }
            m[2L] = CborValue.Text(title)
            m[3L] = CborValue.UInt(start)
            end?.let { m[4L] = CborValue.UInt(it) }
            m[5L] = CborValue.Text(tz)
            location?.let { m[6L] = CborValue.Text(it) }
            m[7L] = CborValue.Bool(allDay)
        }
        is OpBody.EventSet -> {
            m[0L] = CborValue.Bytes(id)
            m[1L] = CborValue.Text(field)
            m[2L] = value.toValueCbor()
        }
        is OpBody.EventCancel -> m[0L] = CborValue.Bytes(id)
        is OpBody.RsvpSet -> {
            m[0L] = CborValue.Bytes(eventId)
            m[1L] = CborValue.Text(value)
        }
        is OpBody.ProfileSet -> {
            m[0L] = CborValue.Text(displayName)
            emoji?.let { m[1L] = CborValue.Text(it) }
        }
        is OpBody.Unknown -> {}
    }
    return CborValue.Map(m)
}

/** Full `{0:type, 1:payload}` CBOR, canonical-encoded - what becomes an [OpEnvelope]'s plaintext. */
public fun OpBody.encode(): ByteArray = CanonicalCborCodec.encode(
    CborValue.Map(linkedMapOf(0L to CborValue.Text(typeName()), 1L to payloadCbor())),
)

/** `null` on malformed CBOR or a shape mismatch for a *known* type - never throws. An unknown
 * `type` string is NOT malformed (PROTOCOL.md §4.2: "Unknown types MUST be ignored") - it decodes
 * to [OpBody.Unknown] successfully. */
public fun decodeOpBody(bytes: ByteArray): OpBody? {
    val top = try {
        CanonicalCborCodec.decode(bytes) as? CborValue.Map ?: return null
    } catch (e: CborFormatException) {
        return null
    }
    val type = (top.entries[0L] as? CborValue.Text)?.value ?: return null
    val payload = (top.entries[1L] as? CborValue.Map)?.entries ?: return null
    return try {
        when (type) {
            "idea.create" -> OpBody.IdeaCreate(
                id = (payload.getValue(0L) as CborValue.Bytes).value,
                title = (payload.getValue(1L) as CborValue.Text).value,
                desc = (payload[2L] as? CborValue.Text)?.value,
                tags = (payload[3L] as? CborValue.Array)?.items?.map { (it as CborValue.Text).value } ?: emptyList(),
            )
            "idea.set" -> OpBody.IdeaSet(
                id = (payload.getValue(0L) as CborValue.Bytes).value,
                field = (payload.getValue(1L) as CborValue.Text).value,
                value = payload.getValue(2L).fromValueCbor(),
            )
            "idea.delete" -> OpBody.IdeaDelete(id = (payload.getValue(0L) as CborValue.Bytes).value)
            "vote.set" -> OpBody.VoteSet(
                ideaId = (payload.getValue(0L) as CborValue.Bytes).value,
                value = payload.getValue(1L).toInt(),
            )
            "comment.add" -> OpBody.CommentAdd(
                id = (payload.getValue(0L) as CborValue.Bytes).value,
                ideaId = (payload.getValue(1L) as CborValue.Bytes).value,
                text = (payload.getValue(2L) as CborValue.Text).value,
            )
            "comment.delete" -> OpBody.CommentDelete(id = (payload.getValue(0L) as CborValue.Bytes).value)
            "event.create" -> OpBody.EventCreate(
                id = (payload.getValue(0L) as CborValue.Bytes).value,
                ideaId = (payload[1L] as? CborValue.Bytes)?.value,
                title = (payload.getValue(2L) as CborValue.Text).value,
                start = (payload.getValue(3L) as CborValue.UInt).value,
                end = (payload[4L] as? CborValue.UInt)?.value,
                tz = (payload.getValue(5L) as CborValue.Text).value,
                location = (payload[6L] as? CborValue.Text)?.value,
                allDay = (payload.getValue(7L) as CborValue.Bool).value,
            )
            "event.set" -> OpBody.EventSet(
                id = (payload.getValue(0L) as CborValue.Bytes).value,
                field = (payload.getValue(1L) as CborValue.Text).value,
                value = payload.getValue(2L).fromValueCbor(),
            )
            "event.cancel" -> OpBody.EventCancel(id = (payload.getValue(0L) as CborValue.Bytes).value)
            "rsvp.set" -> OpBody.RsvpSet(
                eventId = (payload.getValue(0L) as CborValue.Bytes).value,
                value = (payload.getValue(1L) as CborValue.Text).value,
            )
            "profile.set" -> OpBody.ProfileSet(
                displayName = (payload.getValue(0L) as CborValue.Text).value,
                emoji = (payload[1L] as? CborValue.Text)?.value,
            )
            else -> OpBody.Unknown(type)
        }
    } catch (e: NoSuchElementException) {
        null
    } catch (e: ClassCastException) {
        null
    } catch (e: CborFormatException) {
        null
    }
}
