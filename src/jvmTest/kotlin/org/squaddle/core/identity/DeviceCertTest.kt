package org.squaddle.core.identity

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** PROTOCOL.md §2.2 round-trip + reject tests for [DeviceCert]. */
class DeviceCertTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private suspend fun validCert(crypto: Crypto): Pair<DeviceCert, UserIdentity> {
        val identity = UserIdentity.create(crypto)
        val device = crypto.randomBytes(32)
        val cert = DeviceCert.sign(
            crypto = crypto,
            userSecretKey = identity.signing.secretKey,
            user = identity.userKey,
            userBox = identity.userBoxKey,
            device = device,
            label = "Pixel 8",
            issuedAt = 1_700_000_000L,
        )
        return cert to identity
    }

    @Test
    fun validCertVerifies() = runTest {
        val crypto = crypto()
        val (cert, _) = validCert(crypto)
        assertTrue(cert.verify(crypto))
    }

    @Test
    fun rejectsMissingSignature() = runTest {
        val crypto = crypto()
        val (cert, _) = validCert(crypto)
        assertFalse(cert.copy(sig = null).verify(crypto))
    }

    @Test
    fun rejectsTamperedSignature() = runTest {
        val crypto = crypto()
        val (cert, _) = validCert(crypto)
        val tamperedSig = cert.sig!!.copyOf()
        tamperedSig[0] = tamperedSig[0].inc()
        assertFalse(cert.copy(sig = tamperedSig).verify(crypto))
    }

    @Test
    fun rejectsContentTamperedAfterSigning() = runTest {
        val crypto = crypto()
        val (cert, _) = validCert(crypto)
        // Re-assigning the cert to a different device after the fact must invalidate the signature:
        // `device` is part of the signed content.
        assertFalse(cert.copy(device = crypto.randomBytes(32)).verify(crypto))
    }

    @Test
    fun rejectsCrossDomainSignature() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.create(crypto)
        val device = crypto.randomBytes(32)
        val unsigned = DeviceCert(user = identity.userKey, userBox = identity.userBoxKey, device = device, label = "x", issuedAt = 1L)
        // Sign the exact same bytes, but under the "devrevoke" domain instead of "devcert".
        val wrongDomainSig = crypto.sign(
            identity.signing.secretKey,
            crypto.signingInput("devrevoke", CanonicalCborCodec.encode(unsigned.toUnsignedCbor())),
        )
        assertFalse(unsigned.copy(sig = wrongDomainSig).verify(crypto))
    }

    @Test
    fun signRejectsOverLongLabel() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.create(crypto)
        assertFailsWith<IllegalArgumentException> {
            DeviceCert.sign(
                crypto = crypto,
                userSecretKey = identity.signing.secretKey,
                user = identity.userKey,
                userBox = identity.userBoxKey,
                device = crypto.randomBytes(32),
                label = "x".repeat(DeviceCert.MAX_LABEL_LENGTH + 1),
                issuedAt = 1L,
            )
        }
    }

    @Test
    fun verifyRejectsOverLongLabelEvenWithValidSignature() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.create(crypto)
        val unsigned = DeviceCert(
            user = identity.userKey,
            userBox = identity.userBoxKey,
            device = crypto.randomBytes(32),
            label = "x".repeat(DeviceCert.MAX_LABEL_LENGTH + 1),
            issuedAt = 1L,
        )
        val sig = crypto.sign(identity.signing.secretKey, crypto.signingInput(DeviceCert.DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = sig).verify(crypto))
    }

    @Test
    fun verifyRejectsUnknownVersionEvenWithValidSignature() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.create(crypto)
        val unsigned = DeviceCert(
            v = 2,
            user = identity.userKey,
            userBox = identity.userBoxKey,
            device = crypto.randomBytes(32),
            label = "Pixel 8",
            issuedAt = 1L,
        )
        val sig = crypto.sign(identity.signing.secretKey, crypto.signingInput(DeviceCert.DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = sig).verify(crypto))
    }

    @Test
    fun rejectsSignatureFromAnotherUser() = runTest {
        val crypto = crypto()
        val (cert, _) = validCert(crypto)
        val impostor = UserIdentity.create(crypto)
        val forgedSig = crypto.sign(impostor.signing.secretKey, crypto.signingInput(DeviceCert.DOMAIN, CanonicalCborCodec.encode(cert.toUnsignedCbor())))
        assertFalse(cert.copy(sig = forgedSig).verify(crypto))
    }

    @Test
    fun decodeRoundTripsAWireEncodedCert() = runTest {
        val crypto = crypto()
        val (cert, _) = validCert(crypto)
        val decoded = DeviceCert.decode(CanonicalCborCodec.encode(cert.toFullCbor()))!!
        assertTrue(decoded.verify(crypto))
        assertContentEquals(cert.user, decoded.user)
        assertEquals(cert.label, decoded.label)
    }

    @Test
    fun decodeReturnsNullOnMalformedCbor() {
        assertEquals(null, DeviceCert.decode(byteArrayOf(0xff.toByte())))
    }
}
