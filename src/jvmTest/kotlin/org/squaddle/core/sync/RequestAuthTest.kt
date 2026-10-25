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
        val header = RequestAuth.headerValue(crypto, device.secretKey, device.publicKey, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, body)

        val sigB64 = header.substringAfter("sig=")
        val decoded = kotlin.io.encoding.Base64.UrlSafe.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT).decode(sigB64)
        val signingInput = RequestAuth.signingInput(crypto, "POST", "/v1/rooms/abc/ops", 1_700_000_000L, body)
        assertTrue(crypto.verify(device.publicKey, signingInput, decoded))
    }

    @Test
    fun differentBodyProducesDifferentSigningInput() = runTest {
        val crypto = crypto()
        val a = RequestAuth.signingInput(crypto, "GET", "/v1/rooms/abc/log", 1_700_000_000L, ByteArray(0))
        val b = RequestAuth.signingInput(crypto, "GET", "/v1/rooms/abc/log", 1_700_000_000L, "x".encodeToByteArray())
        assertTrue(!a.contentEquals(b))
    }
}
