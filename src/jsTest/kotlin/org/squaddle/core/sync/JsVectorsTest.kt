@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)

package org.squaddle.core.sync

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.identity.UserIdentity
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Real-browser (Karma + headless Chromium) run of two vectors from spec/protocol/testvectors,
 * inlined here rather than loaded from disk - `jvmTest`'s own vector loader
 * (`TestVectorsVerificationTest`) uses `System.getProperty`/`java.io.File`, neither of which
 * exists on this target. Proves `multiplatform-crypto-libsodium-bindings`'s `js` artifact (via
 * the `webpack.config.d/` shim - ADR-0009) actually runs BLAKE2b-256 + Ed25519 inside a real
 * browser JS/WASM engine, not a Node shim.
 */
class JsVectorsTest {

    private fun b64(s: String): ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(s)

    // spec/protocol/testvectors/request-auth.json, vector "request-auth-get-no-query" -
    // BLAKE2b-256 (signingInput) + Ed25519 verify.
    @Test
    fun requestAuthVectorRunsInBrowser() = runTest {
        val crypto = LibsodiumCrypto.create()
        val method = "GET"
        val pathAndQuery = "/v1/rooms/YmFzZTMycm9vbWlk/log"
        val ts = 1700000000L
        val nonce = b64("CgsMDQ4PEBESExQVFhcYGQ")
        val body = b64("")
        val device = b64("MrU-iC49qsGA16X2Ik1htkAbQ_kB2wnw5NhM5OSicYs")

        val signingInput = RequestAuth.signingInput(crypto, method, pathAndQuery, ts, nonce, body)
        assertContentEquals(b64("U1FETDFyZXEAHAF9-1W0Sfoy4J-bmtLjlz298DyyOwC3ujUxIeBKByU"), signingInput)

        val sig = b64("zwQQbom21Xepb1QVMhoZtqRB8zL3rYvqA0ko3wsGrQNawJyKpYjGMpgVv1ZwyorkIKZyt-n-iUwQrXIpO8i3Dw")
        assertTrue(crypto.verify(device, signingInput, sig))
    }

    // spec/protocol/testvectors/identity.json, vector "identity-all-zero" - BLAKE2b-256 (master
    // key) + X25519/Ed25519 key derivation from a BIP39 entropy seed.
    @Test
    fun identityVectorRunsInBrowser() = runTest {
        val crypto = LibsodiumCrypto.create()
        val entropy = b64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        val identity = UserIdentity.fromEntropy(crypto, entropy)
        assertContentEquals(b64("iesNaoppHa4s0V7QNpkxzgqUnsr6XD-T-BIYM2RuFcM"), crypto.blake2b256(entropy))
        assertContentEquals(b64("ouGJcXIzrBC9yTC2F4zdBPWGDhu4J9Nlg3rhS2skc28"), identity.userKey)
        assertContentEquals(b64("dQZ5PPwruIkraocemoj7xeRVVydMv0-bnNa3a45vQ1U"), identity.userBoxKey)
        assertContentEquals(b64("wWMTzHICWxx172U4hzEJOqLecBzLOpin9j722FKtGBQ"), identity.backupKey)
        assertEquals(
            listOf(
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "art",
            ),
            identity.toMnemonic(crypto),
        )
    }
}
