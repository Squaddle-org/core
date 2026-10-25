package org.squaddle.core.ops

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.identity.UserIdentity
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** PROTOCOL.md §4.4 round-trip + reject tests for [Snapshot]. */
class SnapshotTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private suspend fun validSnapshot(crypto: Crypto): Snapshot {
        val identity = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        return Snapshot.sign(
            crypto = crypto,
            deviceSecretKey = device.secretKey,
            room = crypto.randomBytes(32),
            epoch = 2L,
            coversUpTo = 1_000L,
            nonce = crypto.randomBytes(24),
            ct = "opaque-ciphertext".encodeToByteArray(),
            author = identity.userKey,
            device = device.publicKey,
        )
    }

    @Test
    fun validSnapshotVerifies() = runTest {
        val crypto = crypto()
        assertTrue(validSnapshot(crypto).verify(crypto))
    }

    @Test
    fun rejectsMissingSignature() = runTest {
        val crypto = crypto()
        assertFalse(validSnapshot(crypto).copy(sig = null).verify(crypto))
    }

    @Test
    fun rejectsTamperedSignature() = runTest {
        val crypto = crypto()
        val snap = validSnapshot(crypto)
        val tampered = snap.sig!!.copyOf().also { it[0] = it[0].inc() }
        assertFalse(snap.copy(sig = tampered).verify(crypto))
    }

    @Test
    fun rejectsContentTamperedAfterSigning() = runTest {
        val crypto = crypto()
        val snap = validSnapshot(crypto)
        // coversUpTo is part of the signed content - bumping it after signing must invalidate sig.
        assertFalse(snap.copy(coversUpTo = snap.coversUpTo + 1).verify(crypto))
    }

    @Test
    fun rejectsCrossDomainSignature() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val unsigned = Snapshot(
            room = crypto.randomBytes(32), epoch = 0L, coversUpTo = 0L, nonce = crypto.randomBytes(24),
            ct = ByteArray(0), author = identity.userKey, device = device.publicKey,
        )
        val wrongDomainSig = crypto.sign(device.secretKey, crypto.signingInput("op", CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = wrongDomainSig).verify(crypto))
    }

    @Test
    fun rejectsSignatureFromADifferentDevice() = runTest {
        val crypto = crypto()
        val snap = validSnapshot(crypto)
        val otherDevice = crypto.signSeedKeypair(crypto.randomBytes(32))
        val forgedSig = crypto.sign(otherDevice.secretKey, crypto.signingInput(Snapshot.DOMAIN, CanonicalCborCodec.encode(snap.toUnsignedCbor())))
        assertFalse(snap.copy(sig = forgedSig).verify(crypto))
    }

    @Test
    fun rejectsUnknownVersion() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val unsigned = Snapshot(
            v = 2, room = crypto.randomBytes(32), epoch = 0L, coversUpTo = 0L, nonce = crypto.randomBytes(24),
            ct = ByteArray(0), author = identity.userKey, device = device.publicKey,
        )
        val sig = crypto.sign(device.secretKey, crypto.signingInput(Snapshot.DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = sig).verify(crypto))
    }

    @Test
    fun adCborCoversExactlyFieldsZeroToFour() = runTest {
        val crypto = crypto()
        val snap = validSnapshot(crypto)
        val ad = CanonicalCborCodec.encode(snap.toAdCbor())
        val decoded = CanonicalCborCodec.decode(ad)
        assertTrue(decoded is org.squaddle.core.encoding.CborValue.Map)
        // ad must be exactly fields 0..4 - no ct/author/device leaking into the associated data.
        assertTrue(decoded.entries.keys == setOf(0L, 1L, 2L, 3L, 4L))
    }
}
