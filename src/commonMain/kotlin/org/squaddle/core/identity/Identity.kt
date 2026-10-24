package org.squaddle.core.identity

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair

/** PROTOCOL.md §2.1. `entropy` is the 32-byte BIP39 entropy (24 words). */
public class UserIdentity private constructor(
    public val entropy: ByteArray,
    public val signing: KeyPair,
    public val box: KeyPair,
    public val backupKey: ByteArray,
) {
    public val userKey: ByteArray get() = signing.publicKey
    public val userBoxKey: ByteArray get() = box.publicKey

    public fun toMnemonic(crypto: Crypto): List<String> = Bip39.toWords(crypto, entropy)

    public companion object {
        public fun create(crypto: Crypto): UserIdentity = fromEntropy(crypto, crypto.randomBytes(32))

        public fun fromEntropy(crypto: Crypto, entropy: ByteArray): UserIdentity {
            require(entropy.size == 32) { "entropy must be 32 bytes" }
            val master = crypto.blake2b256(entropy)
            val sign = crypto.signSeedKeypair(crypto.kdf(master, 1, "SQDLUSIG"))
            val box = crypto.boxSeedKeypair(crypto.kdf(master, 2, "SQDLUBOX"))
            val backupKey = crypto.kdf(master, 3, "SQDLBKUP")
            return UserIdentity(entropy, sign, box, backupKey)
        }

        /** @throws Bip39.InvalidMnemonicException if [words] is not a valid 24-word BIP39 mnemonic. */
        public fun fromMnemonic(crypto: Crypto, words: List<String>): UserIdentity =
            fromEntropy(crypto, Bip39.fromWords(crypto, words))
    }
}
