package org.squaddle.core.ops

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** PROTOCOL.md §4.1 round-trip + reject tests for [OpEnvelope]. */
class OpEnvelopeTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private class Actor(val identity: UserIdentity, val device: org.squaddle.core.crypto.KeyPair, val cert: DeviceCert)

    private suspend fun actor(crypto: Crypto, label: String): Actor {
        val identity = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, device.publicKey, label, 1_700_000_000L)
        return Actor(identity, device, cert)
    }

    private fun certResolver(vararg actors: Actor): (ByteArray) -> DeviceCert? = { device ->
        actors.firstOrNull { it.device.publicKey.contentEquals(device) }?.cert
    }

    private suspend fun validOp(crypto: Crypto, actor: Actor, epochKey: ByteArray, room: ByteArray, body: OpBody = OpBody.IdeaCreate(crypto.randomBytes(16), "Camping trip", null, emptyList())): OpEnvelope =
        OpEnvelope.create(
            crypto = crypto, deviceSecretKey = actor.device.secretKey, epochKey = epochKey,
            room = room, epoch = 1L, author = actor.identity.userKey, device = actor.device.publicKey,
            seq = 1L, lamport = 1L, body = body,
        )

    @Test
    fun validOpOpensSuccessfully() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val room = crypto.randomBytes(32)
        val epochKey = crypto.randomBytes(32)
        val op = validOp(crypto, a, epochKey, room)

        val result = op.open(crypto, epochKey, certResolver(a))
        assertIs<OpOpenResult.Ok>(result)
        assertIs<OpBody.IdeaCreate>(result.body)
        assertEquals("Camping trip", result.body.title)
    }

    @Test
    fun rejectsMissingSignature() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val op = validOp(crypto, a, crypto.randomBytes(32), crypto.randomBytes(32))
        assertFalse(op.copy(sig = null).verify(crypto))
    }

    @Test
    fun rejectsTamperedSignature() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val epochKey = crypto.randomBytes(32)
        val op = validOp(crypto, a, epochKey, crypto.randomBytes(32))
        val tampered = op.sig!!.copyOf().also { it[0] = it[0].inc() }
        assertFalse(op.copy(sig = tampered).verify(crypto))
    }

    @Test
    fun rejectsContentTamperedAfterSigning() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val op = validOp(crypto, a, crypto.randomBytes(32), crypto.randomBytes(32))
        // lamport is part of both the signed content and the ad - bumping it after signing must
        // invalidate the signature (and, independently, break AEAD ad-matching too).
        assertFalse(op.copy(lamport = op.lamport + 1).verify(crypto))
    }

    @Test
    fun rejectsCrossDomainSignature() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val room = crypto.randomBytes(32)
        val unsigned = OpEnvelope(
            room = room, epoch = 1L, author = a.identity.userKey, device = a.device.publicKey,
            seq = 1L, lamport = 1L, nonce = crypto.randomBytes(24), ct = ByteArray(16),
        )
        val wrongDomainSig = crypto.sign(a.device.secretKey, crypto.signingInput("snapshot", CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = wrongDomainSig).verify(crypto))
    }

    @Test
    fun rejectsSignatureFromADifferentDevice() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val other = actor(crypto, "Other Phone")
        val op = validOp(crypto, a, crypto.randomBytes(32), crypto.randomBytes(32))
        val forgedSig = crypto.sign(other.device.secretKey, crypto.signingInput(OpEnvelope.DOMAIN, CanonicalCborCodec.encode(op.toUnsignedCbor())))
        assertFalse(op.copy(sig = forgedSig).verify(crypto))
    }

    @Test
    fun rejectsUnknownVersion() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val room = crypto.randomBytes(32)
        val unsigned = OpEnvelope(
            v = 2, room = room, epoch = 1L, author = a.identity.userKey, device = a.device.publicKey,
            seq = 1L, lamport = 1L, nonce = crypto.randomBytes(24), ct = ByteArray(16),
        )
        val sig = crypto.sign(a.device.secretKey, crypto.signingInput(OpEnvelope.DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = sig).verify(crypto))
    }

    @Test
    fun rejectsWrongEpochKey() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val op = validOp(crypto, a, crypto.randomBytes(32), crypto.randomBytes(32))
        val result = op.open(crypto, crypto.randomBytes(32), certResolver(a))
        assertIs<OpOpenResult.Reject>(result)
        assertEquals("AEAD authentication failed", result.reason)
    }

    @Test
    fun rejectsDeviceNotCertifiedForAuthor() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val impostor = actor(crypto, "Impostor Phone")
        val epochKey = crypto.randomBytes(32)
        val room = crypto.randomBytes(32)
        // Signed validly by impostor's own device, but claims to be authored by `a`.
        val op = OpEnvelope.create(
            crypto = crypto, deviceSecretKey = impostor.device.secretKey, epochKey = epochKey,
            room = room, epoch = 1L, author = a.identity.userKey, device = impostor.device.publicKey,
            seq = 1L, lamport = 1L, body = OpBody.IdeaCreate(crypto.randomBytes(16), "x", null, emptyList()),
        )
        val result = op.open(crypto, epochKey, certResolver(a, impostor))
        assertIs<OpOpenResult.Reject>(result)
        assertEquals("device not certified for author", result.reason)
    }

    @Test
    fun rejectsUnknownDevice() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val epochKey = crypto.randomBytes(32)
        val op = validOp(crypto, a, epochKey, crypto.randomBytes(32))
        val result = op.open(crypto, epochKey) { null }
        assertIs<OpOpenResult.Reject>(result)
        assertEquals("device not certified for author", result.reason)
    }

    @Test
    fun adCborCoversExactlyFieldsZeroToSeven() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val op = validOp(crypto, a, crypto.randomBytes(32), crypto.randomBytes(32))
        val ad = CanonicalCborCodec.encode(op.toAdCbor())
        val decoded = CanonicalCborCodec.decode(ad)
        assertTrue(decoded is org.squaddle.core.encoding.CborValue.Map)
        assertTrue(decoded.entries.keys == setOf(0L, 1L, 2L, 3L, 4L, 5L, 6L, 7L))
    }

    @Test
    fun decodeRoundTripsAWireEncodedEnvelope() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val epochKey = crypto.randomBytes(32)
        val op = validOp(crypto, a, epochKey, crypto.randomBytes(32))
        val decoded = OpEnvelope.decode(CanonicalCborCodec.encode(op.toFullCbor()))!!
        assertTrue(decoded.verify(crypto))
        assertEquals(op.opId(crypto).toList(), decoded.opId(crypto).toList())
    }

    @Test
    fun decodeReturnsNullOnMalformedCbor() {
        assertEquals(null, OpEnvelope.decode(byteArrayOf(0xff.toByte())))
    }

    @Test
    fun opIdIsStableForIdenticalEnvelopes() = runTest {
        val crypto = crypto()
        val a = actor(crypto, "Phone")
        val op = validOp(crypto, a, crypto.randomBytes(32), crypto.randomBytes(32))
        assertEquals(op.opId(crypto).toList(), op.copy().opId(crypto).toList())
    }
}
