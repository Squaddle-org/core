@file:OptIn(ExperimentalEncodingApi::class)

package org.squaddle.core.testvectors

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonArrayBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.crypto.signingInput
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.identity.Bip39
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import java.io.File
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * `./gradlew generateTestVectors -PspecDir=../spec` - writes identity.json and devicecert.json
 * into `<specDir>/protocol/testvectors/` (core/CLAUDE.md: "never hand-edited" on the spec side).
 * All binary fields are base64url without padding, per testvectors/README.md.
 */
public fun main(args: Array<String>) {
    val specDir = args.getOrNull(0) ?: "../spec"
    val outDir = File(specDir, "protocol/testvectors")
    check(outDir.isDirectory) { "not a directory: $outDir (run with -PspecDir pointing at a spec checkout)" }

    runBlocking {
        val crypto = LibsodiumCrypto.create()
        writeJson(File(outDir, "identity.json"), identityVectors(crypto))
        writeJson(File(outDir, "devicecert.json"), deviceCertVectors(crypto))
    }
}

private fun ByteArray.b64(): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(this)

private fun writeJson(file: File, array: JsonArray) {
    val json = Json { prettyPrint = true }
    file.writeText(json.encodeToString(JsonArray.serializer(), array) + "\n")
    println("wrote ${file.path} (${array.size} vectors)")
}

// ---- identity.json : PROTOCOL.md §2.1 ----

/** Fixed, test-only entropy patterns - vectors must be reproducible, never crypto.randomBytes(). */
private val FIXED_ENTROPIES: List<Pair<String, ByteArray>> = listOf(
    "all-zero" to ByteArray(32),
    "pattern-7f" to ByteArray(32) { 0x7f },
    "pattern-80" to ByteArray(32) { 0x80.toByte() },
    "all-ff" to ByteArray(32) { 0xff.toByte() },
    "incrementing" to ByteArray(32) { it.toByte() },
)

private suspend fun identityVectors(crypto: Crypto): JsonArray = buildJsonArray {
    for ((label, entropy) in FIXED_ENTROPIES) {
        val identity = UserIdentity.fromEntropy(crypto, entropy)
        val mnemonic = identity.toMnemonic(crypto)
        addJsonObject {
            put("name", "identity-$label")
            putJsonObject("input") { put("entropy", entropy.b64()) }
            putJsonObject("expected") {
                putJsonArray("mnemonic") { mnemonic.forEach { add(it) } }
                put("master", crypto.blake2b256(entropy).b64())
                put("userKey", identity.userKey.b64())
                put("userBoxKey", identity.userBoxKey.b64())
                put("backupKey", identity.backupKey.b64())
            }
        }
    }

    val (_, baseEntropy) = FIXED_ENTROPIES[0]
    val baseMnemonic = UserIdentity.fromEntropy(crypto, baseEntropy).toMnemonic(crypto)

    addRejectMnemonic(
        name = "identity-reject-bad-checksum",
        words = baseMnemonic.dropLast(1) + "zoo", // "zoo" is a valid word but breaks the checksum here
        reason = "checksum mismatch",
    )
    addRejectMnemonic(
        name = "identity-reject-word-count",
        words = baseMnemonic.dropLast(1), // 23 words
        reason = "word count must be one of [12, 15, 18, 21, 24]",
    )
    addRejectMnemonic(
        name = "identity-reject-unknown-word",
        words = listOf("squaddle") + baseMnemonic.drop(1),
        reason = "not a BIP39 English wordlist word",
    )
}

private fun JsonArrayBuilder.addRejectMnemonic(name: String, words: List<String>, reason: String) {
    addJsonObject {
        put("name", name)
        putJsonObject("input") { putJsonArray("mnemonic") { words.forEach { add(it) } } }
        putJsonObject("expected") {
            put("accept", false)
            put("reason", reason)
        }
    }
}

// ---- devicecert.json : PROTOCOL.md §2.2 ----

private suspend fun deviceCertVectors(crypto: Crypto): JsonArray = buildJsonArray {
    val userSignSeed = ByteArray(32) { it.toByte() }
    val userBoxSeed = ByteArray(32) { (it + 1).toByte() }
    val userKeys = crypto.signSeedKeypair(userSignSeed)
    val userBoxKeys = crypto.boxSeedKeypair(userBoxSeed)
    val device = ByteArray(32) { (it + 2).toByte() }
    val label = "Pixel 8"
    val issuedAt = 1_700_000_000L

    val valid = DeviceCert.sign(crypto, userKeys.secretKey, userKeys.publicKey, userBoxKeys.publicKey, device, label, issuedAt)
    check(valid.verify(crypto)) { "generator bug: valid DeviceCert vector does not verify" }
    addJsonObject {
        put("name", "devicecert-basic")
        putJsonObject("input") {
            put("user", userKeys.publicKey.b64())
            put("userBox", userBoxKeys.publicKey.b64())
            put("device", device.b64())
            put("label", label)
            put("issuedAt", issuedAt)
        }
        putJsonObject("expected") {
            put("accept", true)
            put("unsignedCbor", CanonicalCborCodec.encode(valid.toUnsignedCbor()).b64())
            put("signingInput", crypto.signingInput(DeviceCert.DOMAIN, CanonicalCborCodec.encode(valid.toUnsignedCbor())).b64())
            put("sig", valid.sig!!.b64())
            put("cbor", CanonicalCborCodec.encode(valid.toFullCbor()).b64())
        }
    }

    val tamperedSig = valid.sig!!.copyOf().also { it[0] = it[0].inc() }
    addRejectDeviceCert(crypto, "devicecert-reject-tampered-signature", valid.copy(sig = tamperedSig), "signature does not verify")

    val crossDomainSig = crypto.sign(userKeys.secretKey, crypto.signingInput("devrevoke", CanonicalCborCodec.encode(valid.toUnsignedCbor())))
    addRejectDeviceCert(crypto, "devicecert-reject-cross-domain-signature", valid.copy(sig = crossDomainSig), "signed under the wrong domain (\"devrevoke\" instead of \"devcert\")")

    val overLongLabelUnsigned = valid.copy(label = "x".repeat(DeviceCert.MAX_LABEL_LENGTH + 1), sig = null)
    val overLongLabelSig = crypto.sign(userKeys.secretKey, crypto.signingInput(DeviceCert.DOMAIN, CanonicalCborCodec.encode(overLongLabelUnsigned.toUnsignedCbor())))
    addRejectDeviceCert(crypto, "devicecert-reject-label-too-long", overLongLabelUnsigned.copy(sig = overLongLabelSig), "label exceeds ${DeviceCert.MAX_LABEL_LENGTH} chars")

    val unknownVersionUnsigned = valid.copy(v = 2, sig = null)
    val unknownVersionSig = crypto.sign(userKeys.secretKey, crypto.signingInput(DeviceCert.DOMAIN, CanonicalCborCodec.encode(unknownVersionUnsigned.toUnsignedCbor())))
    addRejectDeviceCert(crypto, "devicecert-reject-unknown-version", unknownVersionUnsigned.copy(sig = unknownVersionSig), "unknown major v=2")
}

private fun JsonArrayBuilder.addRejectDeviceCert(crypto: Crypto, name: String, cert: DeviceCert, reason: String) {
    check(!cert.verify(crypto)) { "generator bug: reject DeviceCert vector '$name' verifies as valid" }
    addJsonObject {
        put("name", name)
        putJsonObject("input") { put("cbor", CanonicalCborCodec.encode(cert.toFullCbor()).b64()) }
        putJsonObject("expected") {
            put("accept", false)
            put("reason", reason)
        }
    }
}
