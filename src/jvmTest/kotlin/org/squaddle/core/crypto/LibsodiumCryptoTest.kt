package org.squaddle.core.crypto

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Round-trip + reject tests for the libsodium-backed [Crypto] facade (PROTOCOL.md §1). */
class LibsodiumCryptoTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    @Test
    fun randomBytesHasRequestedLengthAndIsNotConstant() = runTest {
        val crypto = crypto()
        val a = crypto.randomBytes(32)
        val b = crypto.randomBytes(32)
        assertEquals(32, a.size)
        assertNotEquals(a.toList(), b.toList())
    }

    @Test
    fun blake2b256IsDeterministicAndSensitiveToInput() = runTest {
        val crypto = crypto()
        val h1 = crypto.blake2b256("hello".encodeToByteArray())
        val h2 = crypto.blake2b256("hello".encodeToByteArray())
        val h3 = crypto.blake2b256("world".encodeToByteArray())
        assertEquals(32, h1.size)
        assertContentEquals(h1, h2)
        assertNotEquals(h1.toList(), h3.toList())
    }

    @Test
    fun blake2b256ConcatenatesAllPartsBeforeHashing() = runTest {
        val crypto = crypto()
        val whole = crypto.blake2b256("foo".encodeToByteArray(), "bar".encodeToByteArray())
        val split = crypto.blake2b256("foobar".encodeToByteArray())
        assertContentEquals(whole, split)
    }

    @Test
    fun signAndVerifyRoundTrip() = runTest {
        val crypto = crypto()
        val keys = crypto.signSeedKeypair(crypto.randomBytes(32))
        val message = "squaddle".encodeToByteArray()
        val sig = crypto.sign(keys.secretKey, message)
        assertTrue(crypto.verify(keys.publicKey, message, sig))
    }

    @Test
    fun verifyRejectsTamperedSignature() = runTest {
        val crypto = crypto()
        val keys = crypto.signSeedKeypair(crypto.randomBytes(32))
        val message = "squaddle".encodeToByteArray()
        val sig = crypto.sign(keys.secretKey, message)
        sig[0] = sig[0].inc()
        assertTrue(!crypto.verify(keys.publicKey, message, sig))
    }

    @Test
    fun verifyRejectsWrongKey() = runTest {
        val crypto = crypto()
        val keys = crypto.signSeedKeypair(crypto.randomBytes(32))
        val other = crypto.signSeedKeypair(crypto.randomBytes(32))
        val message = "squaddle".encodeToByteArray()
        val sig = crypto.sign(keys.secretKey, message)
        assertTrue(!crypto.verify(other.publicKey, message, sig))
    }

    @Test
    fun sealBoxRoundTrip() = runTest {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val plaintext = "secret room key".encodeToByteArray()
        val sealed = crypto.sealBox(recipient.publicKey, plaintext)
        val opened = crypto.openSealedBox(recipient, sealed)
        assertContentEquals(plaintext, opened)
    }

    @Test
    fun openSealedBoxRejectsTamperedCiphertext() = runTest {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val sealed = crypto.sealBox(recipient.publicKey, "secret".encodeToByteArray())
        sealed[sealed.size - 1] = sealed[sealed.size - 1].inc()
        assertNull(crypto.openSealedBox(recipient, sealed))
    }

    @Test
    fun openSealedBoxRejectsWrongRecipient() = runTest {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val stranger = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val sealed = crypto.sealBox(recipient.publicKey, "secret".encodeToByteArray())
        assertNull(crypto.openSealedBox(stranger, sealed))
    }

    @Test
    fun aeadEncryptDecryptRoundTrip() = runTest {
        val crypto = crypto()
        val key = crypto.randomBytes(32)
        val nonce = crypto.randomBytes(24)
        val ad = "room-id".encodeToByteArray()
        val plaintext = "idea: board game night".encodeToByteArray()
        val ct = crypto.aeadEncrypt(key, nonce, plaintext, ad)
        val pt = crypto.aeadDecrypt(key, nonce, ct, ad)
        assertContentEquals(plaintext, pt)
    }

    @Test
    fun aeadDecryptRejectsWrongKey() = runTest {
        val crypto = crypto()
        val key = crypto.randomBytes(32)
        val wrongKey = crypto.randomBytes(32)
        val nonce = crypto.randomBytes(24)
        val ct = crypto.aeadEncrypt(key, nonce, "hi".encodeToByteArray(), ByteArray(0))
        assertNull(crypto.aeadDecrypt(wrongKey, nonce, ct, ByteArray(0)))
    }

    @Test
    fun aeadDecryptRejectsTamperedAssociatedData() = runTest {
        val crypto = crypto()
        val key = crypto.randomBytes(32)
        val nonce = crypto.randomBytes(24)
        val ct = crypto.aeadEncrypt(key, nonce, "hi".encodeToByteArray(), "room-a".encodeToByteArray())
        assertNull(crypto.aeadDecrypt(key, nonce, ct, "room-b".encodeToByteArray()))
    }

    @Test
    fun kdfIsDeterministicAndDomainSeparated() = runTest {
        val crypto = crypto()
        val master = crypto.randomBytes(32)
        val a1 = crypto.kdf(master, 1, "SQDLUSIG")
        val a2 = crypto.kdf(master, 1, "SQDLUSIG")
        val b = crypto.kdf(master, 2, "SQDLUBOX")
        assertContentEquals(a1, a2)
        assertNotEquals(a1.toList(), b.toList())
    }

    @Test
    fun kdfRejectsContextOfWrongLength() = runTest {
        val crypto = crypto()
        val master = crypto.randomBytes(32)
        assertFailsWith<IllegalArgumentException> { crypto.kdf(master, 1, "short") }
    }

    @Test
    fun argon2idIsDeterministicForSameSaltAndSensitiveToPassword() = runTest {
        val crypto = crypto()
        val salt = crypto.randomBytes(16)
        val opsLimit = 3L // crypto_pwhash_OPSLIMIT_MODERATE
        val memLimit = 268435456 // crypto_pwhash_MEMLIMIT_MODERATE
        val a = crypto.argon2id("correct horse".encodeToByteArray(), salt, opsLimit, memLimit)
        val b = crypto.argon2id("correct horse".encodeToByteArray(), salt, opsLimit, memLimit)
        val c = crypto.argon2id("wrong horse".encodeToByteArray(), salt, opsLimit, memLimit)
        assertContentEquals(a, b)
        assertNotEquals(a.toList(), c.toList())
    }

    @Test
    fun signingInputIsDomainSeparated() = runTest {
        val crypto = crypto()
        val body = "some-unsigned-cbor".encodeToByteArray()
        val a = crypto.signingInput("devcert", body)
        val b = crypto.signingInput("devrevoke", body)
        assertNotEquals(a.toList(), b.toList())
    }
}
