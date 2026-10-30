@file:OptIn(ExperimentalJsExport::class)

package org.squaddle.core.jsapi

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.identity.Bip39
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.sync.nowUnixSeconds

/**
 * Everything a caller needs to persist after minting an identity+device, and to show the user
 * their recovery phrase once. `deviceCertIssuedAt` is a `Double`, not a `Long` - JS has no 64-bit
 * integer type and Kotlin/JS exports `Long` unusably across that boundary; a `Double` safely
 * covers unix-second timestamps for the lifetime of this protocol.
 */
@JsExport
public class IdentityResult(
    public val entropy: ByteArray,
    public val userKey: ByteArray,
    public val userBoxKey: ByteArray,
    public val mnemonic: Array<String>,
    public val devicePublicKey: ByteArray,
    public val deviceSecretKey: ByteArray,
    public val deviceCertUser: ByteArray,
    public val deviceCertUserBox: ByteArray,
    public val deviceCertLabel: String,
    public val deviceCertIssuedAt: Double,
    public val deviceCertSig: ByteArray,
)

/**
 * Thin `@JsExport` adapter over core's already-public identity API (ADR-0009) - no protocol
 * logic duplicated here, just a Kotlin/JS-interop-safe shape wrapping [UserIdentity]/
 * [DeviceCert]/[Crypto]: sealed classes, generics and raw `suspend fun`s don't cross the JS
 * export boundary cleanly as-is (a `@JsExport` suspend fun compiles to a Promise-returning JS
 * function - this is what webclient's TypeScript actually calls). Mirrors android's
 * `OnboardingViewModel.finish()`: a device keypair is always freshly minted (PROTOCOL.md §2.1 -
 * it is never derived from the seed), for both create and restore.
 */
@JsExport
public object IdentityApi {
    public suspend fun create(deviceLabel: String): IdentityResult {
        val crypto = LibsodiumCrypto.create()
        return mint(crypto, UserIdentity.create(crypto), deviceLabel)
    }

    /** `null` if [words] is not a valid 24-word BIP39 mnemonic. */
    public suspend fun restore(words: Array<String>, deviceLabel: String): IdentityResult? {
        val crypto = LibsodiumCrypto.create()
        val identity = try {
            UserIdentity.fromMnemonic(crypto, words.toList())
        } catch (e: Bip39.InvalidMnemonicException) {
            return null
        }
        return mint(crypto, identity, deviceLabel)
    }

    /** The backup-file restore path (PROTOCOL.md §7): [entropy] is already decrypted (see
     * `BackupApi.restore`'s own `BackupContentJs.entropy`), so there's no mnemonic to validate -
     * mirrors android's `OnboardingViewModel` using `UserIdentity.fromEntropy` directly for this
     * path instead of round-tripping through words. Same fresh-device-keypair minting as [create]/
     * [restore]. */
    public suspend fun restoreFromEntropy(entropy: ByteArray, deviceLabel: String): IdentityResult {
        val crypto = LibsodiumCrypto.create()
        return mint(crypto, UserIdentity.fromEntropy(crypto, entropy), deviceLabel)
    }

    /** Settings screen's "reveal seed" action - a pure derivation from already-stored [entropy],
     * no device keypair minted (unlike [create]/[restore]/[restoreFromEntropy], which all mint a
     * fresh one): mirrors android's `SettingsViewModel` calling `UserIdentity.toMnemonic`
     * directly on the already-loaded identity, not going through onboarding's mint path again. */
    public suspend fun entropyToMnemonic(entropy: ByteArray): Array<String> {
        val crypto = LibsodiumCrypto.create()
        return UserIdentity.fromEntropy(crypto, entropy).toMnemonic(crypto).toTypedArray()
    }

    private fun mint(crypto: Crypto, identity: UserIdentity, deviceLabel: String): IdentityResult {
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val issuedAt = nowUnixSeconds()
        val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, device.publicKey, deviceLabel, issuedAt)
        return IdentityResult(
            entropy = identity.entropy,
            userKey = identity.userKey,
            userBoxKey = identity.userBoxKey,
            mnemonic = identity.toMnemonic(crypto).toTypedArray(),
            devicePublicKey = device.publicKey,
            deviceSecretKey = device.secretKey,
            deviceCertUser = cert.user,
            deviceCertUserBox = cert.userBox,
            deviceCertLabel = cert.label,
            deviceCertIssuedAt = issuedAt.toDouble(),
            deviceCertSig = requireNotNull(cert.sig) { "DeviceCert.sign always sets sig" },
        )
    }
}
