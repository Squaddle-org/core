package org.squaddle.core.ops

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue

/**
 * PROTOCOL.md §4.4. CBOR field numbers in comments - keep in sync with the spec. Signed by the
 * *device* key named in [device] (field 7), not the user key - same pattern as [OpEnvelope] and
 * `LogEntry`. [verify] is self-contained crypto/structural validity only (known version, Ed25519
 * signature valid under domain "snapshot"); it cannot on its own confirm [device] belongs to
 * [author] - that needs a `/users/{u}/devices` lookup the relay performs, same limitation as
 * [OpEnvelope].
 */
public data class Snapshot(
    val v: Int = 1,              // 0
    val room: ByteArray,         // 1
    val epoch: Long,             // 2
    val coversUpTo: Long,        // 3   ops cursor; this snapshot covers everything up to and incl. it
    val nonce: ByteArray,        // 4
    val ct: ByteArray,           // 5   AEAD(epochKey, nonce, CBOR(materialized state + seq vector), ad = toAdCbor())
    val author: ByteArray,       // 6   userKey
    val device: ByteArray,       // 7   deviceKey
    val sig: ByteArray? = null,  // 8   by device key
) {
    public companion object {
        public const val DOMAIN: String = "snapshot"

        /** Builds and signs a v1 Snapshot with [deviceSecretKey]. [ct] must already be the
         * caller's AEAD-encrypted payload (encrypted using [toAdCbor]'s associated data - a
         * purely client-side step the relay never performs, see package doc). */
        public fun sign(
            crypto: Crypto,
            deviceSecretKey: ByteArray,
            room: ByteArray,
            epoch: Long,
            coversUpTo: Long,
            nonce: ByteArray,
            ct: ByteArray,
            author: ByteArray,
            device: ByteArray,
        ): Snapshot {
            val unsigned = Snapshot(
                v = 1, room = room, epoch = epoch, coversUpTo = coversUpTo, nonce = nonce,
                ct = ct, author = author, device = device,
            )
            val sig = crypto.sign(deviceSecretKey, crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
            return unsigned.copy(sig = sig)
        }
    }

    /** Fields 0..4 (v, room, epoch, coversUpTo, nonce) - the AEAD associated data for [ct],
     * PROTOCOL.md §4.4: "ad = CBOR(fields 0..4)", analogous to [OpEnvelope]'s ad. */
    public fun toAdCbor(): CborValue = CborValue.Map(
        linkedMapOf(
            0L to CborValue.UInt(v.toLong()),
            1L to CborValue.Bytes(room),
            2L to CborValue.UInt(epoch),
            3L to CborValue.UInt(coversUpTo),
            4L to CborValue.Bytes(nonce),
        ),
    )

    /** Fields 0..7, i.e. the struct without [sig] - exactly what is signed over, PROTOCOL.md §1. */
    internal fun toUnsignedCbor(): CborValue {
        val entries = (toAdCbor() as CborValue.Map).entries.toMutableMap()
        entries[5L] = CborValue.Bytes(ct)
        entries[6L] = CborValue.Bytes(author)
        entries[7L] = CborValue.Bytes(device)
        return CborValue.Map(entries)
    }

    /** All fields 0..8 incl. [sig] - what travels on the wire / into test vectors. */
    internal fun toFullCbor(): CborValue {
        val entries = (toUnsignedCbor() as CborValue.Map).entries.toMutableMap()
        sig?.let { entries[8L] = CborValue.Bytes(it) }
        return CborValue.Map(entries)
    }

    public fun verify(crypto: Crypto): Boolean {
        val signature = sig ?: return false
        if (v != 1) return false
        val signingInput = crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(toUnsignedCbor()))
        return crypto.verify(device, signingInput, signature)
    }
}
