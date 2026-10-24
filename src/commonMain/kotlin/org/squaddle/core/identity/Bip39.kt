package org.squaddle.core.identity

import org.squaddle.core.crypto.Crypto

/**
 * BIP39 mnemonic encoding (English wordlist) used by PROTOCOL.md §2.1 to display/import the
 * 32-byte seed entropy. No maintained pure-Kotlin KMP implementation was found (see
 * core/gradle/libs.versions.toml), so this implements the standard directly: entropy -> SHA-256
 * checksum -> 11-bit word indices, and back. SHA-256 here is BIP39's own requirement, not a
 * Squaddle protocol primitive - see [Crypto.sha256].
 */
public object Bip39 {
    private val WORDS = BIP39_ENGLISH_WORDLIST
    private val WORD_INDEX: Map<String, Int> = WORDS.withIndex().associate { (i, w) -> w to i }
    private val VALID_WORD_COUNTS = setOf(12, 15, 18, 21, 24)
    private val VALID_ENTROPY_BYTE_LENGTHS = setOf(16, 20, 24, 28, 32)

    public class InvalidMnemonicException(message: String) : Exception(message)

    /** Entropy -> mnemonic. [entropy] must be 16/20/24/28/32 bytes (128/160/192/224/256 bits). */
    public fun toWords(crypto: Crypto, entropy: ByteArray): List<String> {
        require(entropy.size in VALID_ENTROPY_BYTE_LENGTHS) {
            "entropy must be one of $VALID_ENTROPY_BYTE_LENGTHS bytes, was ${entropy.size}"
        }
        val checksumBitCount = entropy.size / 4 // CS = ENT_bits / 32 = entropy.size*8/32 = entropy.size/4
        val checksum = crypto.sha256(entropy)
        val bits = entropyAndChecksumBits(entropy, checksum, checksumBitCount)
        return bits.toList().chunked(11).map { WORDS[bitsToInt(it)] }
    }

    /** Mnemonic -> entropy. Rejects unknown words, a word count outside {12,15,18,21,24}, and a bad checksum. */
    public fun fromWords(crypto: Crypto, words: List<String>): ByteArray {
        if (words.size !in VALID_WORD_COUNTS) {
            throw InvalidMnemonicException("word count must be one of $VALID_WORD_COUNTS, was ${words.size}")
        }
        val indices = words.map { word ->
            WORD_INDEX[word] ?: throw InvalidMnemonicException("'$word' is not a BIP39 English wordlist word")
        }
        val totalBits = words.size * 11
        val entropyBitCount = totalBits * 32 / 33
        val checksumBitCount = totalBits - entropyBitCount

        val allBits = BooleanArray(totalBits)
        for ((wordPos, index) in indices.withIndex()) {
            for (b in 0 until 11) {
                allBits[wordPos * 11 + b] = (index shr (10 - b)) and 1 == 1
            }
        }

        val entropy = bitsToBytes(allBits.copyOfRange(0, entropyBitCount))
        val expectedChecksumBits = allBits.copyOfRange(entropyBitCount, totalBits)
        val actualChecksum = crypto.sha256(entropy)
        val actualChecksumBits = entropyAndChecksumBits(ByteArray(0), actualChecksum, checksumBitCount)
        if (!expectedChecksumBits.contentEquals(actualChecksumBits)) {
            throw InvalidMnemonicException("checksum mismatch")
        }
        return entropy
    }

    private fun entropyAndChecksumBits(entropy: ByteArray, checksum: ByteArray, checksumBitCount: Int): BooleanArray {
        val bits = BooleanArray(entropy.size * 8 + checksumBitCount)
        for (i in entropy.indices) {
            for (b in 0 until 8) {
                bits[i * 8 + b] = (entropy[i].toInt() shr (7 - b)) and 1 == 1
            }
        }
        val offset = entropy.size * 8
        for (i in 0 until checksumBitCount) {
            val byteIndex = i / 8
            val bitIndex = i % 8
            bits[offset + i] = (checksum[byteIndex].toInt() shr (7 - bitIndex)) and 1 == 1
        }
        return bits
    }

    private fun bitsToInt(bits: List<Boolean>): Int =
        bits.foldIndexed(0) { i, acc, bit -> if (bit) acc or (1 shl (bits.size - 1 - i)) else acc }

    private fun bitsToBytes(bits: BooleanArray): ByteArray {
        val bytes = ByteArray(bits.size / 8)
        for (i in bytes.indices) {
            var b = 0
            for (bit in 0 until 8) {
                if (bits[i * 8 + bit]) b = b or (1 shl (7 - bit))
            }
            bytes[i] = b.toByte()
        }
        return bytes
    }
}
