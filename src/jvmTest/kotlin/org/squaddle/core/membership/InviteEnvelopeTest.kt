package org.squaddle.core.membership

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** PROTOCOL.md §3.5 round-trip + reject tests for [InviteEnvelope]. */
class InviteEnvelopeTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    @Test
    fun sealAndOpenRoundTripWithRoomName() = runTest {
        val crypto = crypto()
        val secret = crypto.randomBytes(32)
        val roomId = crypto.randomBytes(32)
        val inviteId = crypto.randomBytes(16)
        val epochKey = crypto.randomBytes(32)

        val envelope = InviteEnvelope.seal(crypto, secret, roomId, inviteId, epoch = 2L, epochKey = epochKey, roomName = "Board Game Night")
        val opened = InviteEnvelope.open(crypto, secret, roomId, inviteId, envelope)

        assertContentEquals(roomId, opened?.room)
        assertEquals(2L, opened?.epoch)
        assertContentEquals(epochKey, opened?.epochKey)
        assertEquals("Board Game Night", opened?.roomName)
    }

    @Test
    fun sealAndOpenRoundTripWithoutRoomName() = runTest {
        val crypto = crypto()
        val secret = crypto.randomBytes(32)
        val roomId = crypto.randomBytes(32)
        val inviteId = crypto.randomBytes(16)
        val envelope = InviteEnvelope.seal(crypto, secret, roomId, inviteId, epoch = 0L, epochKey = crypto.randomBytes(32))
        assertEquals(null, InviteEnvelope.open(crypto, secret, roomId, inviteId, envelope)?.roomName)
    }

    @Test
    fun inviteKeyIsDeterministicAndSecretSensitive() = runTest {
        val crypto = crypto()
        val secret = crypto.randomBytes(32)
        assertContentEquals(InviteEnvelope.inviteKey(crypto, secret), InviteEnvelope.inviteKey(crypto, secret))
    }

    @Test
    fun openRejectsWrongInviteSecret() = runTest {
        val crypto = crypto()
        val roomId = crypto.randomBytes(32)
        val inviteId = crypto.randomBytes(16)
        val envelope = InviteEnvelope.seal(crypto, crypto.randomBytes(32), roomId, inviteId, 0L, crypto.randomBytes(32))
        assertNull(InviteEnvelope.open(crypto, crypto.randomBytes(32), roomId, inviteId, envelope))
    }

    @Test
    fun openRejectsTamperedCiphertext() = runTest {
        val crypto = crypto()
        val secret = crypto.randomBytes(32)
        val roomId = crypto.randomBytes(32)
        val inviteId = crypto.randomBytes(16)
        val envelope = InviteEnvelope.seal(crypto, secret, roomId, inviteId, 0L, crypto.randomBytes(32))
        envelope[envelope.size - 1] = envelope[envelope.size - 1].inc()
        assertNull(InviteEnvelope.open(crypto, secret, roomId, inviteId, envelope))
    }

    @Test
    fun openRejectsWrongAssociatedData() = runTest {
        val crypto = crypto()
        val secret = crypto.randomBytes(32)
        val roomId = crypto.randomBytes(32)
        val inviteId = crypto.randomBytes(16)
        val envelope = InviteEnvelope.seal(crypto, secret, roomId, inviteId, 0L, crypto.randomBytes(32))
        assertNull(InviteEnvelope.open(crypto, secret, roomId, crypto.randomBytes(16), envelope)) // wrong inviteId as AD
        assertNull(InviteEnvelope.open(crypto, secret, crypto.randomBytes(32), inviteId, envelope)) // wrong roomId as AD
    }

    @Test
    fun openRejectsTruncatedEnvelope() = runTest {
        val crypto = crypto()
        val secret = crypto.randomBytes(32)
        val roomId = crypto.randomBytes(32)
        val inviteId = crypto.randomBytes(16)
        assertNull(InviteEnvelope.open(crypto, secret, roomId, inviteId, ByteArray(10)))
    }
}
