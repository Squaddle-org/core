package org.squaddle.core.identity

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue

/** PROTOCOL.md §2.2. CBOR field numbers in comments — keep in sync with the spec. */
public data class DeviceCert(
    val v: Int = 1,              // 0
    val user: ByteArray,         // 1
    val userBox: ByteArray,      // 2
    val device: ByteArray,       // 3
    val label: String,           // 4
    val issuedAt: Long,          // 5
    val sig: ByteArray? = null,  // 6
) {
    public companion object {
        public const val DOMAIN: String = "devcert"
        public const val MAX_LABEL_LENGTH: Int = 64

        /** Builds and signs a v1 DeviceCert with [userSecretKey] (the user's Ed25519 signing key). */
        public fun sign(
            crypto: Crypto,
            userSecretKey: ByteArray,
            user: ByteArray,
            userBox: ByteArray,
            device: ByteArray,
            label: String,
            issuedAt: Long,
        ): DeviceCert {
            require(label.length <= MAX_LABEL_LENGTH) {
                "label must be at most $MAX_LABEL_LENGTH chars, was ${label.length}"
            }
            val unsigned = DeviceCert(v = 1, user = user, userBox = userBox, device = device, label = label, issuedAt = issuedAt)
            val sig = crypto.sign(userSecretKey, crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
            return unsigned.copy(sig = sig)
        }
    }

    /** Fields 0..5, i.e. the struct without [sig] - exactly what is signed over, PROTOCOL.md §1. */
    internal fun toUnsignedCbor(): CborValue = CborValue.Map(
        linkedMapOf(
            0L to CborValue.UInt(v.toLong()),
            1L to CborValue.Bytes(user),
            2L to CborValue.Bytes(userBox),
            3L to CborValue.Bytes(device),
            4L to CborValue.Text(label),
            5L to CborValue.UInt(issuedAt),
        ),
    )

    /**
     * Verifies [sig] was produced by the user signing key [user] for exactly this cert's content,
     * under the "devcert" domain. Rejects an unknown major [v] and an over-length [label] even if
     * the signature is otherwise valid - PROTOCOL.md §2.2/§9.
     */
    public fun verify(crypto: Crypto): Boolean {
        val signature = sig ?: return false
        if (v != 1) return false
        if (label.length > MAX_LABEL_LENGTH) return false
        val signingInput = crypto.signingInput(DOMAIN, CanonicalCborCodec.encode(toUnsignedCbor()))
        return crypto.verify(user, signingInput, signature)
    }
}
