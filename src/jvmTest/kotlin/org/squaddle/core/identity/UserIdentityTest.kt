package org.squaddle.core.identity

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** PROTOCOL.md §2.1 round-trip + reject tests for [UserIdentity]. */
class UserIdentityTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    @Test
    fun fromEntropyIsDeterministic() = runTest {
        val crypto = crypto()
        val entropy = crypto.randomBytes(32)
        val a = UserIdentity.fromEntropy(crypto, entropy)
        val b = UserIdentity.fromEntropy(crypto, entropy)
        assertContentEquals(a.userKey, b.userKey)
        assertContentEquals(a.userBoxKey, b.userBoxKey)
        assertContentEquals(a.backupKey, b.backupKey)
    }

    @Test
    fun userSigningBoxAndBackupKeysAreAllDifferent() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.fromEntropy(crypto, crypto.randomBytes(32))
        assertNotEquals(identity.userKey.toList(), identity.userBoxKey.toList())
        assertNotEquals(identity.userKey.toList(), identity.backupKey.toList())
        assertNotEquals(identity.userBoxKey.toList(), identity.backupKey.toList())
    }

    @Test
    fun differentEntropyProducesDifferentIdentity() = runTest {
        val crypto = crypto()
        val a = UserIdentity.fromEntropy(crypto, crypto.randomBytes(32))
        val b = UserIdentity.fromEntropy(crypto, crypto.randomBytes(32))
        assertNotEquals(a.userKey.toList(), b.userKey.toList())
    }

    @Test
    fun createGeneratesFreshRandomIdentity() = runTest {
        val crypto = crypto()
        val a = UserIdentity.create(crypto)
        val b = UserIdentity.create(crypto)
        assertNotEquals(a.entropy.toList(), b.entropy.toList())
    }

    @Test
    fun fromEntropyRejectsWrongLength() = runTest {
        val crypto = crypto()
        assertFailsWith<IllegalArgumentException> { UserIdentity.fromEntropy(crypto, ByteArray(16)) }
    }

    @Test
    fun mnemonicRoundTripReconstructsSameIdentity() = runTest {
        val crypto = crypto()
        val original = UserIdentity.create(crypto)
        val words = original.toMnemonic(crypto)
        assertEquals(24, words.size)
        val restored = UserIdentity.fromMnemonic(crypto, words)
        assertContentEquals(original.userKey, restored.userKey)
        assertContentEquals(original.userBoxKey, restored.userBoxKey)
        assertContentEquals(original.backupKey, restored.backupKey)
    }

    @Test
    fun fromMnemonicRejectsInvalidMnemonic() = runTest {
        val crypto = crypto()
        val words = UserIdentity.create(crypto).toMnemonic(crypto).toMutableList()
        words[0] = "squaddle"
        assertFailsWith<Bip39.InvalidMnemonicException> { UserIdentity.fromMnemonic(crypto, words) }
    }

    @Test
    fun userKeyCanSignAndVerifyUnderDerivedIdentity() = runTest {
        val crypto = crypto()
        val identity = UserIdentity.create(crypto)
        val message = "squaddle room".encodeToByteArray()
        val sig = crypto.sign(identity.signing.secretKey, message)
        assertTrue(crypto.verify(identity.userKey, message, sig))
    }
}
