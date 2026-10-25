package org.squaddle.core.backup

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Low (test-only) Argon2id params - never use these for a real backup file. */
private val TEST_PARAMS = Argon2Params(opsLimit = 3L, memLimit = 8 * 1024)

class BackupTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    @Test
    fun createAndRestoreRoundTrips() = runTest {
        val crypto = crypto()
        val passphrase = "correct horse battery staple".encodeToByteArray()
        val content = BackupContent(
            entropy = crypto.randomBytes(32),
            rooms = listOf(BackupRoomRef("ABCDEFG@relay.squaddle.org", "Board Game Night"), BackupRoomRef("HIJKLMN@relay.squaddle.org")),
            createdAt = 1_700_000_000L,
        )
        val file = Backup.create(crypto, passphrase, content, TEST_PARAMS)
        val restored = Backup.restore(crypto, passphrase, file)!!

        assertContentEquals(content.entropy, restored.entropy)
        assertEquals(content.rooms.map { it.roomRef to it.name }, restored.rooms.map { it.roomRef to it.name })
        assertEquals(content.createdAt, restored.createdAt)
    }

    @Test
    fun restoreFailsWithWrongPassphrase() = runTest {
        val crypto = crypto()
        val content = BackupContent(crypto.randomBytes(32), emptyList(), 1L)
        val file = Backup.create(crypto, "correct".encodeToByteArray(), content, TEST_PARAMS)
        assertNull(Backup.restore(crypto, "wrong".encodeToByteArray(), file))
    }

    @Test
    fun restoreFailsOnMalformedFile() = runTest {
        val crypto = crypto()
        assertNull(Backup.restore(crypto, "x".encodeToByteArray(), byteArrayOf(0xff.toByte())))
    }

    @Test
    fun restoreFailsOnTamperedCiphertext() = runTest {
        val crypto = crypto()
        val passphrase = "correct horse battery staple".encodeToByteArray()
        val content = BackupContent(crypto.randomBytes(32), emptyList(), 1L)
        val file = Backup.create(crypto, passphrase, content, TEST_PARAMS)
        val tampered = file.copyOf().also { it[it.size - 1] = it[it.size - 1].inc() }
        assertNull(Backup.restore(crypto, passphrase, tampered))
    }

    @Test
    fun emptyRoomListRoundTrips() = runTest {
        val crypto = crypto()
        val passphrase = "x".encodeToByteArray()
        val content = BackupContent(crypto.randomBytes(32), emptyList(), 0L)
        val file = Backup.create(crypto, passphrase, content, TEST_PARAMS)
        val restored = Backup.restore(crypto, passphrase, file)!!
        assertEquals(emptyList(), restored.rooms)
    }
}
