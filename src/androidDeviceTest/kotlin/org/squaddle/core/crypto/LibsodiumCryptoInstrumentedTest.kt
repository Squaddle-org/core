package org.squaddle.core.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertContentEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * On-device run of the native libsodium bindings (PROTOCOL.md §1) - M0 only verified this on JVM
 * and that the android target compiles; this needs a real device/emulator to actually exercise
 * the bundled .so, which this sandbox doesn't have. Run with `./gradlew connectedAndroidTest`.
 */
@RunWith(AndroidJUnit4::class)
class LibsodiumCryptoInstrumentedTest {

    private fun crypto(): Crypto = runBlocking { LibsodiumCrypto.create() }

    @Test
    fun signAndVerifyRoundTrip() {
        val crypto = crypto()
        val keys = crypto.signSeedKeypair(crypto.randomBytes(32))
        val message = "squaddle-android".encodeToByteArray()
        val sig = crypto.sign(keys.secretKey, message)
        assertTrue(crypto.verify(keys.publicKey, message, sig))
    }

    @Test
    fun sealBoxRoundTrip() {
        val crypto = crypto()
        val recipient = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val plaintext = "secret room key".encodeToByteArray()
        val sealed = crypto.sealBox(recipient.publicKey, plaintext)
        assertContentEquals(plaintext, crypto.openSealedBox(recipient, sealed))
    }

    @Test
    fun aeadEncryptDecryptRoundTrip() {
        val crypto = crypto()
        val key = crypto.randomBytes(32)
        val nonce = crypto.randomBytes(24)
        val ad = "room-id".encodeToByteArray()
        val plaintext = "idea: board game night".encodeToByteArray()
        val ct = crypto.aeadEncrypt(key, nonce, plaintext, ad)
        assertContentEquals(plaintext, crypto.aeadDecrypt(key, nonce, ct, ad))
    }

    @Test
    fun aeadDecryptRejectsWrongKey() {
        val crypto = crypto()
        val key = crypto.randomBytes(32)
        val wrongKey = crypto.randomBytes(32)
        val nonce = crypto.randomBytes(24)
        val ct = crypto.aeadEncrypt(key, nonce, "hi".encodeToByteArray(), ByteArray(0))
        assertNull(crypto.aeadDecrypt(wrongKey, nonce, ct, ByteArray(0)))
    }
}
