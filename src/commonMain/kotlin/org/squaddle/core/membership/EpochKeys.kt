package org.squaddle.core.membership

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue

/** PROTOCOL.md §3.4: `crypto_box_seal(userBoxKey, CBOR{0:room, 1:epoch, 2:epochKey})`. */
public data class EpochKeyWrap(val room: ByteArray, val epoch: Long, val epochKey: ByteArray)

public object EpochKeys {
    /** Wraps [epochKey] for one member's [recipientUserBoxKey]. Call once per member on every rotation. */
    public fun seal(crypto: Crypto, recipientUserBoxKey: ByteArray, room: ByteArray, epoch: Long, epochKey: ByteArray): ByteArray {
        val plaintext = CanonicalCborCodec.encode(
            CborValue.Map(mapOf(0L to CborValue.Bytes(room), 1L to CborValue.UInt(epoch), 2L to CborValue.Bytes(epochKey))),
        )
        return crypto.sealBox(recipientUserBoxKey, plaintext)
    }

    /** `null` if [sealed] doesn't open under [recipientUserBoxKeyPair] or isn't the expected shape - never throws on bad input. */
    public fun open(crypto: Crypto, recipientUserBoxKeyPair: KeyPair, sealed: ByteArray): EpochKeyWrap? {
        val plaintext = crypto.openSealedBox(recipientUserBoxKeyPair, sealed) ?: return null
        val decoded = try {
            CanonicalCborCodec.decode(plaintext)
        } catch (e: CborFormatException) {
            return null
        } as? CborValue.Map ?: return null
        val room = (decoded.entries[0L] as? CborValue.Bytes)?.value ?: return null
        val epoch = (decoded.entries[1L] as? CborValue.UInt)?.value ?: return null
        val epochKey = (decoded.entries[2L] as? CborValue.Bytes)?.value ?: return null
        return EpochKeyWrap(room, epoch, epochKey)
    }
}
