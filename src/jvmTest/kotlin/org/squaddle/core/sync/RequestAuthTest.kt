package org.squaddle.core.sync

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import kotlin.test.Test
import kotlin.test.assertTrue

/** PROTOCOL.md §5 sanity checks for [RequestAuth] - the real cross-implementation check lives in
 * `TestVectorsVerificationTest.requestAuthVectorsVerify()` + relay's own `TestRequestAuthVectors`. */
class RequestAuthTest {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    @Test
    fun headerValueVerifiesAgainstItsOwnSigningInput() = runTest {
        val crypto = crypto()
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val body = "hello".encodeToByteArray()
        val nonce = crypto.randomBytes(16)
        val header = RequestAuth.headerValue(crypto, device.secretKey, device.publicKey, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, nonce, body)

        val sigB64 = header.substringAfter("sig=")
        val decoded = kotlin.io.encoding.Base64.UrlSafe.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT).decode(sigB64)
        val signingInput = RequestAuth.signingInput(crypto, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, nonce, body)
        assertTrue(crypto.verify(device.publicKey, signingInput, decoded))
    }

    @Test
    fun differentBodyProducesDifferentSigningInput() = runTest {
        val crypto = crypto()
        val nonce = crypto.randomBytes(16)
        val a = RequestAuth.signingInput(crypto, "GET", "/v1/rooms/abc/log", 1_700_000_000L, nonce, ByteArray(0))
        val b = RequestAuth.signingInput(crypto, "GET", "/v1/rooms/abc/log", 1_700_000_000L, nonce, "x".encodeToByteArray())
        assertTrue(!a.contentEquals(b))
    }

    @Test
    fun differentNonceProducesDifferentSigningInputAndSignature() = runTest {
        // The fix for the deterministic-Ed25519-signature replay false-positive: two requests
        // identical in every other way (device/method/path/ts/body) must still diverge once their
        // nonces differ, so the relay's nonce-keyed replay cache sees them as distinct requests.
        val crypto = crypto()
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val body = "hello".encodeToByteArray()
        val nonceA = crypto.randomBytes(16)
        val nonceB = crypto.randomBytes(16)

        val signingInputA = RequestAuth.signingInput(crypto, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, nonceA, body)
        val signingInputB = RequestAuth.signingInput(crypto, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, nonceB, body)
        assertTrue(!signingInputA.contentEquals(signingInputB))

        val headerA = RequestAuth.headerValue(crypto, device.secretKey, device.publicKey, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, nonceA, body)
        val headerB = RequestAuth.headerValue(crypto, device.secretKey, device.publicKey, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, nonceB, body)
        assertTrue(headerA != headerB)
    }
}
