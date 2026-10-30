package org.squaddle.core.link

import kotlinx.coroutines.test.runTest
import org.squaddle.core.backup.BackupRoomRef
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.identity.UserIdentity
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceLinkTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    @Test
    fun sealAndOpenRoundTrips() = runTest {
        val crypto = crypto()
        val generated = DeviceLink.generate(crypto, "relay.squaddle.org")
        val entropy = crypto.randomBytes(32)
        val expectedUserKey = UserIdentity.fromEntropy(crypto, entropy).userKey
        val rooms = listOf(BackupRoomRef("ABCDEFG@relay.squaddle.org", "Board Game Night"), BackupRoomRef("HIJKLMN@relay.squaddle.org"))

        val sealed = DeviceLink.sealForLink(crypto, generated.qr, entropy, rooms)
        val ephemeralKeyPair = KeyPair(generated.qr.ephemeralPublicKey, generated.ephemeralSecretKey)
        val opened = DeviceLink.openLinkedIdentity(crypto, ephemeralKeyPair, sealed)!!

        assertContentEquals(entropy, opened.entropy)
        assertContentEquals(expectedUserKey, opened.userKey)
        assertEquals(rooms.map { it.roomRef to it.name }, opened.rooms.map { it.roomRef to it.name })
    }

    @Test
    fun emptyRoomListRoundTrips() = runTest {
        val crypto = crypto()
        val generated = DeviceLink.generate(crypto, "relay.squaddle.org")
        val entropy = crypto.randomBytes(32)
        val sealed = DeviceLink.sealForLink(crypto, generated.qr, entropy, emptyList())
        val opened = DeviceLink.openLinkedIdentity(crypto, KeyPair(generated.qr.ephemeralPublicKey, generated.ephemeralSecretKey), sealed)!!
        assertEquals(emptyList(), opened.rooms)
    }

    @Test
    fun openFailsWithWrongEphemeralKeypair() = runTest {
        val crypto = crypto()
        val generated = DeviceLink.generate(crypto, "relay.squaddle.org")
        val otherGenerated = DeviceLink.generate(crypto, "relay.squaddle.org")
        val sealed = DeviceLink.sealForLink(crypto, generated.qr, crypto.randomBytes(32), emptyList())
        val wrongKeyPair = KeyPair(otherGenerated.qr.ephemeralPublicKey, otherGenerated.ephemeralSecretKey)
        assertNull(DeviceLink.openLinkedIdentity(crypto, wrongKeyPair, sealed))
    }

    @Test
    fun openFailsOnMalformedBlob() = runTest {
        val crypto = crypto()
        val generated = DeviceLink.generate(crypto, "relay.squaddle.org")
        val ephemeralKeyPair = KeyPair(generated.qr.ephemeralPublicKey, generated.ephemeralSecretKey)
        assertNull(DeviceLink.openLinkedIdentity(crypto, ephemeralKeyPair, byteArrayOf(0xff.toByte())))
    }

    @Test
    fun openFailsOnTamperedCiphertext() = runTest {
        val crypto = crypto()
        val generated = DeviceLink.generate(crypto, "relay.squaddle.org")
        val sealed = DeviceLink.sealForLink(crypto, generated.qr, crypto.randomBytes(32), emptyList())
        val tampered = sealed.copyOf().also { it[it.size - 1] = it[it.size - 1].inc() }
        val ephemeralKeyPair = KeyPair(generated.qr.ephemeralPublicKey, generated.ephemeralSecretKey)
        assertNull(DeviceLink.openLinkedIdentity(crypto, ephemeralKeyPair, tampered))
    }

    @Test
    fun qrUriRoundTrips() = runTest {
        val generated = DeviceLink.generate(crypto(), "relay.squaddle.org")
        val uri = generated.qr.toUri()
        val parsed = LinkQr.parse(uri)!!
        assertEquals(generated.qr.relayHost, parsed.relayHost)
        assertContentEquals(generated.qr.code, parsed.code)
        assertContentEquals(generated.qr.ephemeralPublicKey, parsed.ephemeralPublicKey)
    }

    @Test
    fun qrUriRoundTripsWithAPortInRelayHost() {
        val qr = LinkQr("localhost:18080", byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
        val parsed = LinkQr.parse(qr.toUri())!!
        assertEquals("localhost:18080", parsed.relayHost)
        assertContentEquals(qr.code, parsed.code)
        assertContentEquals(qr.ephemeralPublicKey, parsed.ephemeralPublicKey)
    }

    @Test
    fun parseRejectsGarbage() {
        assertNull(LinkQr.parse("not a link uri at all"))
        assertNull(LinkQr.parse("squaddle-link:v1:relay.squaddle.org"))
        assertNull(LinkQr.parse("squaddle-link:v1:relay.squaddle.org:not-base64:also-not-base64"))
    }

    @Test
    fun confirmationCodeIsAlwaysSixDigitsAndDeterministic() = runTest {
        val crypto = crypto()
        repeat(50) {
            val ek = crypto.randomBytes(32)
            val userKey = crypto.randomBytes(32)
            val code = DeviceLink.confirmationCode(crypto, ek, userKey)
            assertEquals(6, code.length)
            assertTrue(code.all { it.isDigit() })
            assertEquals(code, DeviceLink.confirmationCode(crypto, ek, userKey))
        }
    }
}
