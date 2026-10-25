package org.squaddle.core.membership

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** PROTOCOL.md §3.2 round-trip + reject tests for [LogEntry] (crypto/structural validity only - chain and §3.3 authorization are [MembershipState]'s job). */
class LogEntryTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private class Actor(val identity: UserIdentity, val deviceKey: org.squaddle.core.crypto.KeyPair, val cert: DeviceCert)

    private suspend fun actor(crypto: Crypto, label: String = "device"): Actor {
        val identity = UserIdentity.create(crypto)
        val deviceKey = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, deviceKey.publicKey, label, 1L)
        return Actor(identity, deviceKey, cert)
    }

    private fun entry(crypto: Crypto, actor: Actor, room: ByteArray, index: Long = 0, prev: ByteArray? = null): LogEntry =
        LogEntry.sign(
            crypto = crypto,
            deviceSecretKey = actor.deviceKey.secretKey,
            room = room,
            index = index,
            prev = prev,
            author = actor.identity.userKey,
            cert = actor.cert,
            type = EntryType.ROOM_SETTINGS,
            body = CborValue.Map(emptyMap()),
            ts = 1_700_000_000L,
        )

    @Test
    fun validEntryVerifies() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        assertTrue(entry(crypto, a, crypto.randomBytes(32)).verify(crypto))
    }

    @Test
    fun entryHashIsDeterministicAndSensitiveToContent() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val room = crypto.randomBytes(32)
        val e1 = entry(crypto, a, room)
        val e2 = entry(crypto, a, room)
        // Ed25519 is deterministic (unlike ECDSA/Schnorr): identical content + key -> identical sig/hash.
        assertContentEquals(e1.sig!!, e2.sig!!)
        assertContentEquals(e1.entryHash(crypto), e2.entryHash(crypto))
        assertNotEquals(e1.entryHash(crypto).toList(), entry(crypto, a, crypto.randomBytes(32)).entryHash(crypto).toList())
    }

    @Test
    fun rejectsTamperedSignature() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val e = entry(crypto, a, crypto.randomBytes(32))
        val tampered = e.sig!!.copyOf().also { it[0] = it[0].inc() }
        assertFalse(e.copy(sig = tampered).verify(crypto))
    }

    @Test
    fun rejectsContentTamperedAfterSigning() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val e = entry(crypto, a, crypto.randomBytes(32))
        assertFalse(e.copy(ts = e.ts + 1).verify(crypto))
    }

    @Test
    fun rejectsCrossDomainSignature() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val unsigned = LogEntry(
            room = crypto.randomBytes(32), index = 0, prev = null, author = a.identity.userKey,
            cert = a.cert, type = EntryType.ROOM_SETTINGS, body = CborValue.Map(emptyMap()), ts = 1L,
        )
        val wrongDomainSig = crypto.sign(a.deviceKey.secretKey, crypto.signingInput("devcert", CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = wrongDomainSig).verify(crypto))
    }

    @Test
    fun rejectsSignatureFromADifferentDevice() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val e = entry(crypto, a, crypto.randomBytes(32))
        val otherDevice = crypto.signSeedKeypair(crypto.randomBytes(32))
        val forgedSig = crypto.sign(otherDevice.secretKey, crypto.signingInput(LogEntry.DOMAIN, CanonicalCborCodec.encode(e.toUnsignedCbor())))
        assertFalse(e.copy(sig = forgedSig).verify(crypto))
    }

    @Test
    fun rejectsWhenCertUserDoesNotMatchAuthor() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val impostor = UserIdentity.create(crypto)
        // Author claims to be `impostor`, but the attached cert (and its signature) is still `a`'s.
        val e = entry(crypto, a, crypto.randomBytes(32)).copy(author = impostor.userKey)
        assertFalse(e.verify(crypto))
    }

    @Test
    fun rejectsWhenCertItselfIsInvalid() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val tamperedCert = a.cert.copy(sig = a.cert.sig!!.copyOf().also { it[0] = it[0].inc() })
        val e = entry(crypto, a, crypto.randomBytes(32)).copy(cert = tamperedCert)
        assertFalse(e.verify(crypto))
    }

    @Test
    fun rejectsUnknownVersion() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val unsigned = LogEntry(
            v = 2, room = crypto.randomBytes(32), index = 0, prev = null, author = a.identity.userKey,
            cert = a.cert, type = EntryType.ROOM_SETTINGS, body = CborValue.Map(emptyMap()), ts = 1L,
        )
        val sig = crypto.sign(a.deviceKey.secretKey, crypto.signingInput(LogEntry.DOMAIN, CanonicalCborCodec.encode(unsigned.toUnsignedCbor())))
        assertFalse(unsigned.copy(sig = sig).verify(crypto))
    }

    @Test
    fun genesisHasNoPrevButLaterEntriesDo() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val room = crypto.randomBytes(32)
        val genesis = entry(crypto, a, room, index = 0, prev = null)
        val second = entry(crypto, a, room, index = 1, prev = genesis.entryHash(crypto))
        assertTrue(genesis.verify(crypto))
        assertTrue(second.verify(crypto))
        assertContentEquals(genesis.entryHash(crypto), second.prev!!)
    }

    @Test
    fun decodeRoundTripsAWireEncodedEntry() = runTest {
        val crypto = crypto()
        val a = actor(crypto)
        val room = crypto.randomBytes(32)
        val original = entry(crypto, a, room)
        val decoded = LogEntry.decode(CanonicalCborCodec.encode(original.toFullCbor()))!!
        assertTrue(decoded.verify(crypto))
        assertContentEquals(original.entryHash(crypto), decoded.entryHash(crypto))
    }

    @Test
    fun decodeReturnsNullOnMalformedCbor() {
        kotlin.test.assertEquals(null, LogEntry.decode(byteArrayOf(0xff.toByte())))
    }
}
