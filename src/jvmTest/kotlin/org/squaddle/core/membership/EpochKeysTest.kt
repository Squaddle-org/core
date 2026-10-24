package org.squaddle.core.membership

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** PROTOCOL.md §3.4 round-trip + reject tests for [EpochKeys]. */
class EpochKeysTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    @Test
    fun sealAndOpenRoundTrip() = runTest {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val room = crypto.randomBytes(32)
        val epoch = 3L
        val epochKey = crypto.randomBytes(32)

        val sealed = EpochKeys.seal(crypto, recipient.publicKey, room, epoch, epochKey)
        val opened = EpochKeys.open(crypto, recipient, sealed)

        assertContentEquals(room, opened?.room)
        assertEquals(epoch, opened?.epoch)
        assertContentEquals(epochKey, opened?.epochKey)
    }

    @Test
    fun openReturnsNullForWrongRecipient() = runTest {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val stranger = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val sealed = EpochKeys.seal(crypto, recipient.publicKey, crypto.randomBytes(32), 0L, crypto.randomBytes(32))
        assertNull(EpochKeys.open(crypto, stranger, sealed))
    }

    @Test
    fun openReturnsNullForTamperedCiphertext() = runTest {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val sealed = EpochKeys.seal(crypto, recipient.publicKey, crypto.randomBytes(32), 0L, crypto.randomBytes(32))
        sealed[sealed.size - 1] = sealed[sealed.size - 1].inc()
        assertNull(EpochKeys.open(crypto, recipient, sealed))
    }

    @Test
    fun openReturnsNullForWrongShape() = runTest {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        // Opens fine as a sealed box, but the plaintext isn't the expected {0:room,1:epoch,2:epochKey} map.
        val sealed = crypto.sealBox(recipient.publicKey, CanonicalCborCodec.encode(CborValue.UInt(42)))
        assertNull(EpochKeys.open(crypto, recipient, sealed))
    }
}
