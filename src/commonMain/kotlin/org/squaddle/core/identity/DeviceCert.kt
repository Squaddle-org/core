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

        /** Decodes a full (0..6, incl. [sig]) CBOR-encoded DeviceCert as received from the wire
         * (e.g. embedded in a `LogEntry`, or fetched via `/users/{u}/devices`). `null` on
         * malformed CBOR or a field-shape mismatch - never throws; does NOT verify the signature,
         * call [verify] for that. Mirrors relay's own `DecodeDeviceCert`. */
        public fun decode(bytes: ByteArray): DeviceCert? {
            val map = try {
                (CanonicalCborCodec.decode(bytes) as? CborValue.Map)?.entries ?: return null
            } catch (e: org.squaddle.core.encoding.CborFormatException) {
                return null
            }
            return try {
                DeviceCert(
                    v = (map.getValue(0L) as CborValue.UInt).value.toInt(),
                    user = (map.getValue(1L) as CborValue.Bytes).value,
                    userBox = (map.getValue(2L) as CborValue.Bytes).value,
                    device = (map.getValue(3L) as CborValue.Bytes).value,
                    label = (map.getValue(4L) as CborValue.Text).value,
                    issuedAt = (map.getValue(5L) as CborValue.UInt).value,
                    sig = (map[6L] as? CborValue.Bytes)?.value,
                )
            } catch (e: NoSuchElementException) {
                null
            } catch (e: ClassCastException) {
                null
            }
        }

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

    /** All fields 0..6 incl. [sig], e.g. for test vectors or putting a signed cert on the wire. */
    internal fun toFullCbor(): CborValue {
        val entries = (toUnsignedCbor() as CborValue.Map).entries.toMutableMap()
        sig?.let { entries[6L] = CborValue.Bytes(it) }
        return CborValue.Map(entries)
    }

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
