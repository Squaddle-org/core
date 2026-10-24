package org.squaddle.core.membership

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue

/** PROTOCOL.md §3.5: `inviteKey → nonce ‖ AEAD(inviteKey, nonce, CBOR{0:room,1:epoch,2:epochKey,3:roomName?}, ad=roomId‖inviteId)`. */
public data class InviteEnvelopeContent(val room: ByteArray, val epoch: Long, val epochKey: ByteArray, val roomName: String?)

public object InviteEnvelope {
    private const val NONCE_LENGTH = 24

    /** `inviteKey = kdf(BLAKE2b(inviteSecret), id=1, ctx="SQDLINVK")`. [inviteSecret] is the 32
     * random bytes that live only in the invite URL fragment - never sent to any server. */
    public fun inviteKey(crypto: Crypto, inviteSecret: ByteArray): ByteArray =
        crypto.kdf(crypto.blake2b256(inviteSecret), 1, "SQDLINVK")

    /**
     * Only for invites without approval (§3.5) - for approval invites the key arrives in `approve`
     * instead. [nonce] defaults to a fresh random one (PROTOCOL.md §1: nonces random 24 bytes) -
     * the override exists only so test-vector generation can produce reproducible envelope bytes;
     * production callers MUST NOT pass a fixed nonce.
     */
    public fun seal(
        crypto: Crypto,
        inviteSecret: ByteArray,
        roomId: ByteArray,
        inviteId: ByteArray,
        epoch: Long,
        epochKey: ByteArray,
        roomName: String? = null,
        nonce: ByteArray = crypto.randomBytes(NONCE_LENGTH),
    ): ByteArray {
        val plaintext = CanonicalCborCodec.encode(
            CborValue.Map(
                buildMap {
                    put(0L, CborValue.Bytes(roomId))
                    put(1L, CborValue.UInt(epoch))
                    put(2L, CborValue.Bytes(epochKey))
                    roomName?.let { put(3L, CborValue.Text(it)) }
                },
            ),
        )
        val ct = crypto.aeadEncrypt(inviteKey(crypto, inviteSecret), nonce, plaintext, roomId + inviteId)
        return nonce + ct
    }

    /** `null` (never throws) if [envelope] doesn't decrypt under [inviteSecret]/[roomId]/[inviteId], or isn't the expected shape. */
    public fun open(crypto: Crypto, inviteSecret: ByteArray, roomId: ByteArray, inviteId: ByteArray, envelope: ByteArray): InviteEnvelopeContent? {
        if (envelope.size < NONCE_LENGTH) return null
        val nonce = envelope.copyOfRange(0, NONCE_LENGTH)
        val ct = envelope.copyOfRange(NONCE_LENGTH, envelope.size)
        val plaintext = crypto.aeadDecrypt(inviteKey(crypto, inviteSecret), nonce, ct, roomId + inviteId) ?: return null
        val decoded = try {
            CanonicalCborCodec.decode(plaintext)
        } catch (e: CborFormatException) {
            return null
        } as? CborValue.Map ?: return null
        val room = (decoded.entries[0L] as? CborValue.Bytes)?.value ?: return null
        val epoch = (decoded.entries[1L] as? CborValue.UInt)?.value ?: return null
        val epochKey = (decoded.entries[2L] as? CborValue.Bytes)?.value ?: return null
        val roomName = (decoded.entries[3L] as? CborValue.Text)?.value
        return InviteEnvelopeContent(room, epoch, epochKey, roomName)
    }
}
