package org.squaddle.core.identity

import kotlinx.coroutines.test.runTest
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Round-trip + reject tests for [Bip39], cross-checked against the trezor/python-mnemonic BIP39 test vectors. */
class Bip39Test {

    private suspend fun crypto(): Crypto = LibsodiumCrypto.create()

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> ((hex[2 * i].digitToInt(16) shl 4) or hex[2 * i + 1].digitToInt(16)).toByte() }

    // 256-bit entropy cases from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    private val referenceVectors = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000" to
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f" to
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "8080808080808080808080808080808080808080808080808080808080808080" to
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" to
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    )

    @Test
    fun matchesReferenceVectorsEntropyToWords() = runTest {
        val crypto = crypto()
        for ((entropyHex, expectedMnemonic) in referenceVectors) {
            val entropy = hexToBytes(entropyHex)
            assertEquals(32, entropy.size)
            val words = Bip39.toWords(crypto, entropy)
            assertEquals(expectedMnemonic.split(" "), words, "entropy $entropyHex")
        }
    }

    @Test
    fun matchesReferenceVectorsWordsToEntropy() = runTest {
        val crypto = crypto()
        for ((entropyHex, mnemonic) in referenceVectors) {
            val entropy = Bip39.fromWords(crypto, mnemonic.split(" "))
            assertContentEquals(hexToBytes(entropyHex), entropy, "mnemonic '$mnemonic'")
        }
    }

    @Test
    fun randomEntropyRoundTrips() = runTest {
        val crypto = crypto()
        val entropy = crypto.randomBytes(32)
        val words = Bip39.toWords(crypto, entropy)
        assertEquals(24, words.size)
        assertContentEquals(entropy, Bip39.fromWords(crypto, words))
    }

    @Test
    fun toWordsRejectsWrongEntropyLength() = runTest {
        val crypto = crypto()
        assertFailsWith<IllegalArgumentException> { Bip39.toWords(crypto, ByteArray(31)) }
    }

    @Test
    fun fromWordsRejectsWrongWordCount() = runTest {
        val crypto = crypto()
        val words = referenceVectors[0].second.split(" ").dropLast(1) // 23 words
        assertFailsWith<Bip39.InvalidMnemonicException> { Bip39.fromWords(crypto, words) }
    }

    @Test
    fun fromWordsRejectsUnknownWord() = runTest {
        val crypto = crypto()
        val words = referenceVectors[0].second.split(" ").toMutableList()
        words[0] = "squaddle" // not in the BIP39 wordlist
        assertFailsWith<Bip39.InvalidMnemonicException> { Bip39.fromWords(crypto, words) }
    }

    @Test
    fun fromWordsRejectsBadChecksum() = runTest {
        val crypto = crypto()
        // Last word of the all-zero vector ("art") carries the checksum; swap in the wrong last word
        // from a different vector so every entropy bit matches except the checksum.
        val words = referenceVectors[0].second.split(" ").toMutableList()
        words[words.size - 1] = referenceVectors[3].second.split(" ").last() // "vote" instead of "art"
        assertFailsWith<Bip39.InvalidMnemonicException> { Bip39.fromWords(crypto, words) }
    }
}
