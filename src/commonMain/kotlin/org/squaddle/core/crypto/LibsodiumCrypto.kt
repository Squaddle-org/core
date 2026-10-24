@file:OptIn(ExperimentalUnsignedTypes::class)

package org.squaddle.core.crypto

import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.aead.AuthenticatedEncryptionWithAssociatedData
import com.ionspin.kotlin.crypto.aead.AeadCorrupedOrTamperedDataException
import com.ionspin.kotlin.crypto.box.Box
import com.ionspin.kotlin.crypto.box.BoxCorruptedOrTamperedDataException
import com.ionspin.kotlin.crypto.generichash.GenericHash
import com.ionspin.kotlin.crypto.generichash.crypto_generichash_BYTES
import com.ionspin.kotlin.crypto.kdf.Kdf
import com.ionspin.kotlin.crypto.pwhash.PasswordHash
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_argon2id_ALG_ARGON2ID13
import com.ionspin.kotlin.crypto.signature.InvalidSignatureException
import com.ionspin.kotlin.crypto.signature.Signature
import com.ionspin.kotlin.crypto.util.LibsodiumRandom

/**
 * [Crypto] on top of `com.ionspin.kotlin:multiplatform-crypto-libsodium-bindings`.
 * Must go through [create] so libsodium is initialized before any call.
 */
public class LibsodiumCrypto private constructor() : Crypto {

    override fun randomBytes(n: Int): ByteArray =
        LibsodiumRandom.buf(n).toByteArray()

    override fun blake2b256(vararg parts: ByteArray): ByteArray {
        val message = concat(parts)
        return GenericHash.genericHash(message.toUByteArray(), crypto_generichash_BYTES).toByteArray()
    }

    override fun signSeedKeypair(seed32: ByteArray): KeyPair {
        val pair = Signature.seedKeypair(seed32.toUByteArray())
        return KeyPair(pair.publicKey.toByteArray(), pair.secretKey.toByteArray())
    }

    override fun sign(secretKey: ByteArray, message: ByteArray): ByteArray =
        Signature.detached(message.toUByteArray(), secretKey.toUByteArray()).toByteArray()

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        try {
            Signature.verifyDetached(signature.toUByteArray(), message.toUByteArray(), publicKey.toUByteArray())
            true
        } catch (e: InvalidSignatureException) {
            false
        }

    override fun boxSeedKeypair(seed32: ByteArray): KeyPair {
        val pair = Box.seedKeypair(seed32.toUByteArray())
        return KeyPair(pair.publicKey.toByteArray(), pair.secretKey.toByteArray())
    }

    override fun sealBox(recipientPk: ByteArray, plaintext: ByteArray): ByteArray =
        Box.seal(plaintext.toUByteArray(), recipientPk.toUByteArray()).toByteArray()

    override fun openSealedBox(recipient: KeyPair, ciphertext: ByteArray): ByteArray? =
        try {
            Box.sealOpen(ciphertext.toUByteArray(), recipient.publicKey.toUByteArray(), recipient.secretKey.toUByteArray())
                .toByteArray()
        } catch (e: BoxCorruptedOrTamperedDataException) {
            null
        } catch (e: IndexOutOfBoundsException) {
            null
        }

    override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray =
        AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfEncrypt(
            plaintext.toUByteArray(), ad.toUByteArray(), nonce.toUByteArray(), key.toUByteArray(),
        ).toByteArray()

    override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray? =
        try {
            AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfDecrypt(
                ciphertext.toUByteArray(), ad.toUByteArray(), nonce.toUByteArray(), key.toUByteArray(),
            ).toByteArray()
        } catch (e: AeadCorrupedOrTamperedDataException) {
            null
        } catch (e: IndexOutOfBoundsException) {
            null
        }

    override fun kdf(master32: ByteArray, id: Long, context: String): ByteArray {
        require(context.length == 8) { "crypto_kdf context must be exactly 8 ASCII chars, was '$context'" }
        return Kdf.deriveFromKey(id.toUInt(), 32, context, master32.toUByteArray()).toByteArray()
    }

    override fun argon2id(password: ByteArray, salt16: ByteArray, opsLimit: Long, memLimit: Int): ByteArray =
        PasswordHash.pwhash(
            outputLength = 32,
            password = password.decodeToString(),
            salt = salt16.toUByteArray(),
            opsLimit = opsLimit.toULong(),
            memLimit = memLimit,
            algorithm = crypto_pwhash_argon2id_ALG_ARGON2ID13,
        ).toByteArray()

    public companion object {
        /** Initializes libsodium (loads the native/WASM module) and returns a ready-to-use facade. */
        public suspend fun create(): LibsodiumCrypto {
            if (!LibsodiumInitializer.isInitialized()) {
                LibsodiumInitializer.initialize()
            }
            return LibsodiumCrypto()
        }
    }
}

private fun concat(parts: Array<out ByteArray>): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var offset = 0
    for (part in parts) {
        part.copyInto(out, offset)
        offset += part.size
    }
    return out
}
