package org.squaddle.core.crypto

/**
 * Thin facade over libsodium. The ONLY place in the codebase that touches crypto primitives.
 * Implement on top of com.ionspin.kotlin.crypto (call LibsodiumInitializer.initialize() once).
 * See spec: protocol/PROTOCOL.md §1.
 */
public interface Crypto {
    public fun randomBytes(n: Int): ByteArray
    public fun blake2b256(vararg parts: ByteArray): ByteArray

    /** SHA-256. Only used for the BIP39 mnemonic checksum (§2.1) - that standard mandates it, not a
     * Squaddle-protocol primitive; every signed/hashed Squaddle structure still uses [blake2b256]. */
    public fun sha256(data: ByteArray): ByteArray

    public fun signSeedKeypair(seed32: ByteArray): KeyPair
    public fun sign(secretKey: ByteArray, message: ByteArray): ByteArray
    public fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    public fun boxSeedKeypair(seed32: ByteArray): KeyPair
    public fun sealBox(recipientPk: ByteArray, plaintext: ByteArray): ByteArray
    public fun openSealedBox(recipient: KeyPair, ciphertext: ByteArray): ByteArray?

    /** XChaCha20-Poly1305-IETF. Nonce MUST be 24 random bytes. */
    public fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray
    public fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray?

    /** crypto_kdf_derive_from_key, context exactly 8 ASCII chars. */
    public fun kdf(master32: ByteArray, id: Long, context: String): ByteArray

    public fun argon2id(password: ByteArray, salt16: ByteArray, opsLimit: Long, memLimit: Int): ByteArray
}

public class KeyPair(public val publicKey: ByteArray, public val secretKey: ByteArray)

/** Domain-separated signing input, PROTOCOL.md §1 "Signing rule". */
public fun Crypto.signingInput(domain: String, unsignedCbor: ByteArray): ByteArray =
    "SQDL1".encodeToByteArray() + domain.encodeToByteArray() + byteArrayOf(0) + blake2b256(unsignedCbor)
