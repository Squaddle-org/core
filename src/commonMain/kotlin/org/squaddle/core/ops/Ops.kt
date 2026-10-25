package org.squaddle.core.ops

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert

/**
 * PROTOCOL.md §4.1. CBOR field numbers follow declaration order (0..9). Signed by the *device*
 * key named in [device] (field 4), not the user key - same pattern as [Snapshot] and `LogEntry`.
 */
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
    val sig: ByteArray? = null,
) {
    public companion object {
        public const val DOMAIN: String = "op"

        /** Builds, encrypts and signs a v1 OpEnvelope: [body]'s plaintext CBOR becomes [ct] under
         * `AEAD(epochKey, nonce, CBOR(body), ad = toAdCbor())`. */
        public fun create(
            crypto: Crypto,
            deviceSecretKey: ByteArray,
            epochKey: ByteArray,
            room: ByteArray,
            epoch: Long,
            author: ByteArray,
            device: ByteArray,
            seq: Long,
            lamport: Long,
            body: OpBody,
            nonce: ByteArray = crypto.randomBytes(24),
        ): OpEnvelope {
            val withoutCt = OpEnvelope(v = 1, room = room, epoch = epoch, author = author, device = device, seq = seq, lamport = lamport, nonce = nonce, ct = ByteArray(0))
            val ad = CanonicalCborCodec.encode(withoutCt.toAdCbor())
            val ct = crypto.aeadEncrypt(epochKey, nonce, body.encode(), ad)
            return sign(crypto, deviceSecretKey, room, epoch, author, device, seq, lamport, nonce, ct)
        }

        /** Low-level: signs an already-encrypted envelope - vector generation needs explicit
         * control over [ct] (e.g. to encrypt under one epoch key and then open under another). */
        public fun sign(
            crypto: Crypto,
            deviceSecretKey: ByteArray,
            room: ByteArray,
            epoch: Long,
            author: ByteArray,
            device: ByteArray,
            seq: Long,
            lamport: Long,
            nonce: ByteArray,
            ct: ByteArray,
        ): OpEnvelope {
            val unsigned = OpEnvelope(v = 1, room = room, epoch = epoch, author = author, device = device, seq = seq, lamport = lamport, nonce = nonce, ct = ct)
            val sig = crypto.sign(deviceSecretKey, crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
            return unsigned.copy(sig = sig)
        }
    }

    /** Fields 0..7 (v, room, epoch, author, device, seq, lamport, nonce) - the AEAD associated
     * data for [ct], PROTOCOL.md §4.1: "ad = CBOR(fields 0..7 without ct)". */
    public fun toAdCbor(): CborValue = CborValue.Map(
        linkedMapOf(
            0L to CborValue.UInt(v.toLong()),
            1L to CborValue.Bytes(room),
            2L to CborValue.UInt(epoch),
            3L to CborValue.Bytes(author),
            4L to CborValue.Bytes(device),
            5L to CborValue.UInt(seq),
            6L to CborValue.UInt(lamport),
            7L to CborValue.Bytes(nonce),
        ),
    )

    /** Fields 0..8, i.e. the struct without [sig] - exactly what is signed over. */
    internal fun toUnsignedCbor(): CborValue {
        val entries = (toAdCbor() as CborValue.Map).entries.toMutableMap()
        entries[8L] = CborValue.Bytes(ct)
        return CborValue.Map(entries)
    }

    /** All fields 0..9 incl. [sig] - what `opId` is computed over and what travels on the wire. */
    public fun toFullCbor(): CborValue {
        val entries = (toUnsignedCbor() as CborValue.Map).entries.toMutableMap()
        sig?.let { entries[9L] = CborValue.Bytes(it) }
        return CborValue.Map(entries)
    }

    /** `opId = BLAKE2b(CBOR(full envelope))`, PROTOCOL.md §4.1. */
    public fun opId(crypto: Crypto): ByteArray = crypto.blake2b256(CanonicalCborCodec.encode(toFullCbor()))

    /** Self-contained crypto/structural validity only: known version and a valid Ed25519
     * signature by [device] under domain "op". Does NOT check that [device] belongs to [author]
     * or that [ct] decrypts - use [open] for the full check. */
    public fun verify(crypto: Crypto): Boolean {
        val signature = sig ?: return false
        if (v != 1) return false
        val signingInput = crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(toUnsignedCbor()))
        return crypto.verify(device, signingInput, signature)
    }

    /**
     * Full open: signature, then that [device] is actually certified for [author] (via
     * [certOf] - a local cert lookup, e.g. backed by the room's membership log, mirroring the
     * `/users/{u}/devices` check the relay does for the same structural limitation), then AEAD
     * decryption (covers both a wrong epoch key and a tampered [ad] - both just surface as one
     * AEAD-authentication failure, same as [org.squaddle.core.membership.InviteEnvelope]'s own
     * reject case), then CBOR-decoding the plaintext into an [OpBody].
     */
    public fun open(crypto: Crypto, epochKey: ByteArray, certOf: (device: ByteArray) -> DeviceCert?): OpOpenResult {
        if (!verify(crypto)) return OpOpenResult.Reject("signature does not verify")
        val cert = certOf(device) ?: return OpOpenResult.Reject("device not certified for author")
        if (!cert.user.contentEquals(author)) return OpOpenResult.Reject("device not certified for author")
        val ad = CanonicalCborCodec.encode(toAdCbor())
        val plaintext = crypto.aeadDecrypt(epochKey, nonce, ct, ad) ?: return OpOpenResult.Reject("AEAD authentication failed")
        val body = decodeOpBody(plaintext) ?: return OpOpenResult.Reject("malformed op body")
        return OpOpenResult.Ok(body)
    }
}

public sealed interface OpOpenResult {
    public data class Ok(public val body: OpBody) : OpOpenResult
    public data class Reject(public val reason: String) : OpOpenResult
}

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
