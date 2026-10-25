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
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.Bip39
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.InviteEnvelope
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipRejectException
import org.squaddle.core.membership.MembershipState
import org.squaddle.core.membership.MembershipStateImpl
import org.squaddle.core.membership.RejectReason
import org.squaddle.core.membership.StoredEntry
import org.squaddle.core.membership.roomId
import org.squaddle.core.ops.OpBody
import org.squaddle.core.ops.OpEnvelope
import org.squaddle.core.ops.OpOpenResult
import org.squaddle.core.ops.Snapshot
import org.squaddle.core.ops.encode
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
        writeJson(File(outDir, "cbor-reject.json"), cborRejectVectors())
        writeJson(File(outDir, "identity.json"), identityVectors(crypto))
        writeJson(File(outDir, "devicecert.json"), deviceCertVectors(crypto))
        writeJson(File(outDir, "logentry.json"), logEntryVectors(crypto))
        writeJson(File(outDir, "log-reject.json"), logRejectVectors(crypto))
        writeJson(File(outDir, "invite.json"), inviteVectors(crypto))
        writeJson(File(outDir, "snapshot.json"), snapshotVectors(crypto))
        writeJson(File(outDir, "op.json"), opVectors(crypto))
    }
}

private fun ByteArray.b64(): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(this)

private fun writeJson(file: File, array: JsonArray) {
    val json = Json { prettyPrint = true }
    file.writeText(json.encodeToString(JsonArray.serializer(), array) + "\n")
    println("wrote ${file.path} (${array.size} vectors)")
}

// ---- cbor-reject.json : PROTOCOL.md §1 "A decoder MUST reject ..." ----

private fun cborRejectVectors(): JsonArray = buildJsonArray {
    val acceptCases = listOf(
        "uint-0" to CborValue.UInt(0),
        "uint-23" to CborValue.UInt(23),
        "uint-24" to CborValue.UInt(24),
        "uint-255" to CborValue.UInt(255),
        "uint-256" to CborValue.UInt(256),
        "uint-65535" to CborValue.UInt(65535),
        "uint-65536" to CborValue.UInt(65536),
        "uint-4294967295" to CborValue.UInt(4294967295L),
        "uint-4294967296" to CborValue.UInt(4294967296L),
        "bool-true" to CborValue.Bool(true),
        "bool-false" to CborValue.Bool(false),
        "null" to CborValue.Null,
        "sorted-map" to CborValue.Map(linkedMapOf(0L to CborValue.UInt(2), 2L to CborValue.UInt(3), 5L to CborValue.UInt(1))),
    )
    for ((name, value) in acceptCases) {
        val encoded = CanonicalCborCodec.encode(value)
        check(CanonicalCborCodec.decode(encoded) == value) { "generator bug: cbor-reject accept case '$name' does not round-trip" }
        addJsonObject {
            put("name", "cbor-accept-$name")
            putJsonObject("input") { put("cbor", encoded.b64()) }
            putJsonObject("expected") { put("accept", true) }
        }
    }

    val rejectCases = listOf(
        "indefinite-length-map" to (byteArrayOf(0xbf.toByte(), 0xff.toByte()) to "indefinite-length items are not canonical"),
        "overlong-int-encoding" to (byteArrayOf(0x18, 0x00) to "non-shortest-form integer/length encoding"),
        "out-of-order-map-keys" to (byteArrayOf(0xa2.toByte(), 0x02, 0x00, 0x00, 0x00) to "map keys not in strictly ascending canonical order"),
        "duplicate-map-keys" to (byteArrayOf(0xa2.toByte(), 0x00, 0x00, 0x00, 0x01) to "map keys not in strictly ascending canonical order (duplicate)"),
        "trailing-bytes" to (CanonicalCborCodec.encode(CborValue.UInt(1)) + byteArrayOf(0x00) to "trailing bytes after top-level value"),
        "truncated-input" to (byteArrayOf(0x19, 0x01) to "unexpected end of input"),
    )
    for ((name, pair) in rejectCases) {
        val (bytes, reason) = pair
        check(runCatching { CanonicalCborCodec.decode(bytes) }.isFailure) { "generator bug: cbor-reject case '$name' does not fail to decode" }
        addJsonObject {
            put("name", "cbor-reject-$name")
            putJsonObject("input") { put("cbor", bytes.b64()) }
            putJsonObject("expected") {
                put("accept", false)
                put("reason", reason)
            }
        }
    }
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

// ---- membership (logentry.json / log-reject.json / invite.json) : PROTOCOL.md §3 ----

private data class FixedActor(val identity: UserIdentity, val deviceKey: org.squaddle.core.crypto.KeyPair, val cert: DeviceCert)

/** [seed]s must be spaced far enough apart (multiples of 100 here) that entropy/deviceSeed byte
 * patterns of different actors never collide. Fixed, test-only - never crypto.randomBytes(). */
private fun fixedActor(crypto: Crypto, seed: Int, label: String): FixedActor {
    val entropy = ByteArray(32) { (it + seed).toByte() }
    val deviceSeed = ByteArray(32) { (it + seed + 1).toByte() }
    val identity = UserIdentity.fromEntropy(crypto, entropy)
    val deviceKey = crypto.signSeedKeypair(deviceSeed)
    val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, deviceKey.publicKey, label, 1_700_000_000L)
    return FixedActor(identity, deviceKey, cert)
}

private fun entryTypeName(type: EntryType): String = when (type) {
    EntryType.GENESIS -> "genesis"
    EntryType.INVITE_CREATE -> "inviteCreate"
    EntryType.INVITE_REVOKE -> "inviteRevoke"
    EntryType.JOIN -> "join"
    EntryType.APPROVE -> "approve"
    EntryType.REJECT -> "reject"
    EntryType.REMOVE -> "remove"
    EntryType.LEAVE -> "leave"
    EntryType.SET_ROLE -> "setRole"
    EntryType.TRANSFER_OWNER -> "transferOwner"
    EntryType.EPOCH_ROTATE -> "epochRotate"
    EntryType.ROOM_SETTINGS -> "roomSettings"
}

private fun genesisBody(nonce: ByteArray) = CborValue.Map(linkedMapOf(
    0L to CborValue.Bytes(nonce),
    1L to CborValue.Text("relay.squaddle.org"),
    2L to CborValue.Bytes(ByteArray(48)),
))
private fun inviteCreateBody(inviteId: ByteArray, requiresApproval: Boolean = false) = CborValue.Map(linkedMapOf(
    0L to CborValue.Bytes(inviteId),
    3L to CborValue.Bool(requiresApproval),
    4L to CborValue.Text("member"),
))
private fun joinBody(inviteId: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(inviteId)))
private fun approveBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user), 1L to CborValue.Bytes(ByteArray(32))))
private fun removeBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user)))
private fun leaveBody() = CborValue.Map(emptyMap())
private fun setRoleBody(user: ByteArray, role: String) = CborValue.Map(mapOf(0L to CborValue.Bytes(user), 1L to CborValue.Text(role)))
private fun transferOwnerBody(user: ByteArray) = CborValue.Map(mapOf(0L to CborValue.Bytes(user)))
private fun epochRotateBody(epoch: Long, users: List<ByteArray>) = CborValue.Map(mapOf(
    0L to CborValue.UInt(epoch),
    1L to CborValue.Array(users.map { CborValue.Map(mapOf(0L to CborValue.Bytes(it), 1L to CborValue.Bytes(ByteArray(48)))) }),
))
private fun roomSettingsBody() = CborValue.Map(emptyMap())

/** Drives one room's log for vector generation - mirrors core's own MembershipStateTest helper. */
private class Chain(val crypto: Crypto, val roomId: ByteArray) {
    var state: MembershipState = MembershipStateImpl.empty(crypto)
    var index: Long = 0L
    var head: ByteArray? = null
    val appliedEntries = mutableListOf<LogEntry>()

    /** Entry paired with the state immediately after it was applied - so a vector can record
     * derived fields like `rotationPending` per step, not just the entry's own bytes. */
    val appliedSteps = mutableListOf<Pair<LogEntry, MembershipState>>()

    fun build(actor: FixedActor, type: EntryType, body: CborValue.Map): LogEntry =
        LogEntry.sign(crypto, actor.deviceKey.secretKey, roomId, index, head, actor.identity.userKey, actor.cert, type, body, 1_700_000_000L + index)

    fun apply(entry: LogEntry, rts: Long = 1_700_000_500L): MembershipState {
        state = state.apply(StoredEntry(entry, rts)).getOrThrow()
        index = entry.index + 1
        head = entry.entryHash(crypto)
        appliedEntries += entry
        appliedSteps += entry to state
        return state
    }

    fun rejects(entry: LogEntry, rts: Long = 1_700_000_500L): RejectReason {
        val result = state.apply(StoredEntry(entry, rts))
        return (result.exceptionOrNull() as? MembershipRejectException)?.reason
            ?: error("generator bug: expected a reject, got $result")
    }
}

private fun logEntryVectors(crypto: Crypto): JsonArray = buildJsonArray {
    val roomNonce = ByteArray(16) { (it + 40).toByte() }
    val owner = fixedActor(crypto, 0, "Owner Phone")
    val member = fixedActor(crypto, 1000, "Member Phone")
    val inviteId = ByteArray(16) { (it + 50).toByte() }
    val rid = roomId(crypto, owner.identity.userKey, roomNonce)
    val chain = Chain(crypto, rid)

    chain.apply(chain.build(owner, EntryType.GENESIS, genesisBody(roomNonce)))
    chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(inviteId)))
    chain.apply(chain.build(member, EntryType.JOIN, joinBody(inviteId)))
    chain.apply(chain.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey, member.identity.userKey))))
    chain.apply(chain.build(owner, EntryType.REMOVE, removeBody(member.identity.userKey)))
    chain.apply(chain.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(2, listOf(owner.identity.userKey))))

    addJsonObject {
        put("name", "logentry-chain")
        putJsonObject("input") { put("room", rid.b64()) }
        putJsonObject("expected") {
            putJsonArray("entries") {
                for ((e, stateAfter) in chain.appliedSteps) {
                    addJsonObject {
                        put("index", e.index)
                        put("type", entryTypeName(e.type))
                        put("cbor", CanonicalCborCodec.encode(e.toFullCbor()).b64())
                        put("entryHash", e.entryHash(crypto).b64())
                        put("rotationPending", stateAfter.rotationPending)
                    }
                }
            }
        }
    }
}

private fun JsonArrayBuilder.addLogReject(roomId: ByteArray, name: String, prefix: List<LogEntry>, bad: LogEntry, reason: RejectReason) {
    addJsonObject {
        put("name", name)
        putJsonObject("input") {
            put("room", roomId.b64())
            putJsonArray("prefix") { prefix.forEach { add(CanonicalCborCodec.encode(it.toFullCbor()).b64()) } }
            put("entry", CanonicalCborCodec.encode(bad.toFullCbor()).b64())
        }
        putJsonObject("expected") {
            put("accept", false)
            put("reason", reason.toString())
        }
    }
}

/** One reject vector per §3.3 row, plus one chain-level (not type-specific) stale-head case. */
private fun logRejectVectors(crypto: Crypto): JsonArray = buildJsonArray {
    val owner = fixedActor(crypto, 0, "Owner Phone")
    val member = fixedActor(crypto, 1000, "Member Phone")
    val admin = fixedActor(crypto, 2000, "Admin Phone")

    fun freshChain(): Pair<Chain, ByteArray> {
        val nonce = ByteArray(16) { (it + 40).toByte() }
        val rid = roomId(crypto, owner.identity.userKey, nonce)
        val chain = Chain(crypto, rid)
        chain.apply(chain.build(owner, EntryType.GENESIS, genesisBody(nonce)))
        return chain to rid
    }

    // row 0: genesis - re-genesis after the room already exists
    run {
        val (chain, rid) = freshChain()
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(owner, EntryType.GENESIS, genesisBody(ByteArray(16) { (it + 90).toByte() }))
        addLogReject(rid, "log-reject-re-genesis", prefix, bad, chain.rejects(bad))
    }

    // row 1: inviteCreate - non-admin author
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        chain.apply(chain.build(member, EntryType.JOIN, joinBody(invite0)))
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(member, EntryType.INVITE_CREATE, inviteCreateBody(ByteArray(16) { (it + 51).toByte() }))
        addLogReject(rid, "log-reject-inviteCreate-unauthorized", prefix, bad, chain.rejects(bad))
    }

    // row 2: inviteRevoke - non-admin author
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        chain.apply(chain.build(member, EntryType.JOIN, joinBody(invite0)))
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(member, EntryType.INVITE_REVOKE, CborValue.Map(mapOf(0L to CborValue.Bytes(invite0))))
        addLogReject(rid, "log-reject-inviteRevoke-unauthorized", prefix, bad, chain.rejects(bad))
    }

    // row 3: join - revoked invite
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        chain.apply(chain.build(owner, EntryType.INVITE_REVOKE, CborValue.Map(mapOf(0L to CborValue.Bytes(invite0)))))
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(member, EntryType.JOIN, joinBody(invite0))
        addLogReject(rid, "log-reject-join-invite-revoked", prefix, bad, chain.rejects(bad))
    }

    // row 4: approve - target not pending
    run {
        val (chain, rid) = freshChain()
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(owner, EntryType.APPROVE, approveBody(owner.identity.userKey))
        addLogReject(rid, "log-reject-approve-target-not-pending", prefix, bad, chain.rejects(bad))
    }

    // row 5: reject - target not pending
    run {
        val (chain, rid) = freshChain()
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(owner, EntryType.REJECT, CborValue.Map(mapOf(0L to CborValue.Bytes(owner.identity.userKey))))
        addLogReject(rid, "log-reject-reject-target-not-pending", prefix, bad, chain.rejects(bad))
    }

    // row 6: remove - owner cannot remove self
    run {
        val (chain, rid) = freshChain()
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(owner, EntryType.REMOVE, removeBody(owner.identity.userKey))
        addLogReject(rid, "log-reject-remove-owner-self", prefix, bad, chain.rejects(bad))
    }

    // row 7: leave - owner must transferOwner first
    run {
        val (chain, rid) = freshChain()
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(owner, EntryType.LEAVE, leaveBody())
        addLogReject(rid, "log-reject-leave-owner-must-transfer", prefix, bad, chain.rejects(bad))
    }

    // row 8: setRole - non-owner author
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        chain.apply(chain.build(admin, EntryType.JOIN, joinBody(invite0)))
        chain.apply(chain.build(member, EntryType.JOIN, joinBody(invite0)))
        chain.apply(chain.build(owner, EntryType.SET_ROLE, setRoleBody(admin.identity.userKey, "admin")))
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(admin, EntryType.SET_ROLE, setRoleBody(member.identity.userKey, "admin"))
        addLogReject(rid, "log-reject-setRole-non-owner", prefix, bad, chain.rejects(bad))
    }

    // row 9: transferOwner - target not currently admin
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        chain.apply(chain.build(member, EntryType.JOIN, joinBody(invite0)))
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(owner, EntryType.TRANSFER_OWNER, transferOwnerBody(member.identity.userKey))
        addLogReject(rid, "log-reject-transferOwner-target-not-admin", prefix, bad, chain.rejects(bad))
    }

    // row 10: epochRotate - incomplete member set
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        chain.apply(chain.build(member, EntryType.JOIN, joinBody(invite0)))
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(owner, EntryType.EPOCH_ROTATE, epochRotateBody(1, listOf(owner.identity.userKey))) // missing member
        addLogReject(rid, "log-reject-epochRotate-incomplete-members", prefix, bad, chain.rejects(bad))
    }

    // row 11: roomSettings - non-admin author
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        chain.apply(chain.build(member, EntryType.JOIN, joinBody(invite0)))
        val prefix = chain.appliedEntries.toList()
        val bad = chain.build(member, EntryType.ROOM_SETTINGS, roomSettingsBody())
        addLogReject(rid, "log-reject-roomSettings-unauthorized", prefix, bad, chain.rejects(bad))
    }

    // chain-level (not type-specific): stale head, as if two clients raced on the same prev
    run {
        val (chain, rid) = freshChain()
        val invite0 = ByteArray(16) { (it + 50).toByte() }
        val staleHead = chain.head
        val staleIndex = chain.index
        chain.apply(chain.build(owner, EntryType.INVITE_CREATE, inviteCreateBody(invite0)))
        val prefix = chain.appliedEntries.toList()
        val bad = LogEntry.sign(crypto, member.deviceKey.secretKey, rid, staleIndex, staleHead, member.identity.userKey, member.cert, EntryType.JOIN, joinBody(invite0), 1L)
        addLogReject(rid, "log-reject-stale-head", prefix, bad, chain.rejects(bad))
    }
}

private fun inviteVectors(crypto: Crypto): JsonArray = buildJsonArray {
    val inviteSecret = ByteArray(32) { (it + 80).toByte() }
    val roomIdBytes = ByteArray(32) { (it + 90).toByte() }
    val inviteId = ByteArray(16) { (it + 100).toByte() }
    val epochKey = ByteArray(32) { (it + 110).toByte() }
    val roomName = "Board Game Night"
    val nonce = ByteArray(24) { (it + 120).toByte() } // fixed: vectors must be reproducible, never crypto.randomBytes()

    val envelope = InviteEnvelope.seal(crypto, inviteSecret, roomIdBytes, inviteId, epoch = 0L, epochKey = epochKey, roomName = roomName, nonce = nonce)
    val opened = InviteEnvelope.open(crypto, inviteSecret, roomIdBytes, inviteId, envelope)
    check(opened != null && opened.epoch == 0L && opened.roomName == roomName) { "generator bug: invite envelope round trip failed" }

    addJsonObject {
        put("name", "invite-basic")
        putJsonObject("input") {
            put("inviteSecret", inviteSecret.b64())
            put("roomId", roomIdBytes.b64())
            put("inviteId", inviteId.b64())
            put("epoch", 0L)
            put("epochKey", epochKey.b64())
            put("roomName", roomName)
        }
        putJsonObject("expected") {
            put("accept", true)
            put("inviteKey", InviteEnvelope.inviteKey(crypto, inviteSecret).b64())
            put("envelope", envelope.b64())
        }
    }

    val tampered = envelope.copyOf().also { it[it.size - 1] = it[it.size - 1].inc() }
    check(InviteEnvelope.open(crypto, inviteSecret, roomIdBytes, inviteId, tampered) == null) { "generator bug: tampered invite envelope still opens" }
    addJsonObject {
        put("name", "invite-reject-tampered-ciphertext")
        putJsonObject("input") {
            put("inviteSecret", inviteSecret.b64())
            put("roomId", roomIdBytes.b64())
            put("inviteId", inviteId.b64())
            put("envelope", tampered.b64())
        }
        putJsonObject("expected") {
            put("accept", false)
            put("reason", "AEAD authentication failed")
        }
    }
}

// ---- snapshot.json : PROTOCOL.md §4.4 ----

private fun snapshotVectors(crypto: Crypto): JsonArray = buildJsonArray {
    val userSignSeed = ByteArray(32) { (it + 130).toByte() }
    val userKeys = crypto.signSeedKeypair(userSignSeed)
    val deviceSeed = ByteArray(32) { (it + 140).toByte() }
    val deviceKeys = crypto.signSeedKeypair(deviceSeed)
    val room = ByteArray(32) { (it + 150).toByte() }
    val epoch = 3L
    val coversUpTo = 1_234L
    val nonce = ByteArray(24) { (it + 160).toByte() } // fixed: vectors must be reproducible, never crypto.randomBytes()
    val ct = ByteArray(48) { (it + 170).toByte() } // opaque AEAD ciphertext bytes - relay never decrypts this

    val valid = Snapshot.sign(
        crypto = crypto,
        deviceSecretKey = deviceKeys.secretKey,
        room = room,
        epoch = epoch,
        coversUpTo = coversUpTo,
        nonce = nonce,
        ct = ct,
        author = userKeys.publicKey,
        device = deviceKeys.publicKey,
    )
    check(valid.verify(crypto)) { "generator bug: valid Snapshot vector does not verify" }
    addJsonObject {
        put("name", "snapshot-basic")
        putJsonObject("input") {
            put("room", room.b64())
            put("epoch", epoch)
            put("coversUpTo", coversUpTo)
            put("nonce", nonce.b64())
            put("ct", ct.b64())
            put("author", userKeys.publicKey.b64())
            put("device", deviceKeys.publicKey.b64())
        }
        putJsonObject("expected") {
            put("accept", true)
            put("ad", CanonicalCborCodec.encode(valid.toAdCbor()).b64())
            put("unsignedCbor", CanonicalCborCodec.encode(valid.toUnsignedCbor()).b64())
            put("signingInput", crypto.signingInput(Snapshot.DOMAIN, CanonicalCborCodec.encode(valid.toUnsignedCbor())).b64())
            put("sig", valid.sig!!.b64())
            put("cbor", CanonicalCborCodec.encode(valid.toFullCbor()).b64())
        }
    }

    val tamperedSig = valid.sig!!.copyOf().also { it[0] = it[0].inc() }
    addRejectSnapshot(crypto, "snapshot-reject-tampered-signature", valid.copy(sig = tamperedSig), "signature does not verify")

    val crossDomainSig = crypto.sign(deviceKeys.secretKey, crypto.signingInput("op", CanonicalCborCodec.encode(valid.toUnsignedCbor())))
    addRejectSnapshot(crypto, "snapshot-reject-cross-domain-signature", valid.copy(sig = crossDomainSig), "signed under the wrong domain (\"op\" instead of \"snapshot\")")

    val unknownVersionUnsigned = valid.copy(v = 2, sig = null)
    val unknownVersionSig = crypto.sign(deviceKeys.secretKey, crypto.signingInput(Snapshot.DOMAIN, CanonicalCborCodec.encode(unknownVersionUnsigned.toUnsignedCbor())))
    addRejectSnapshot(crypto, "snapshot-reject-unknown-version", unknownVersionUnsigned.copy(sig = unknownVersionSig), "unknown major v=2")
}

private fun JsonArrayBuilder.addRejectSnapshot(crypto: Crypto, name: String, snapshot: Snapshot, reason: String) {
    check(!snapshot.verify(crypto)) { "generator bug: reject Snapshot vector '$name' verifies as valid" }
    addJsonObject {
        put("name", name)
        putJsonObject("input") { put("cbor", CanonicalCborCodec.encode(snapshot.toFullCbor()).b64()) }
        putJsonObject("expected") {
            put("accept", false)
            put("reason", reason)
        }
    }
}

// ---- op.json : PROTOCOL.md §4.1 ----

private fun opVectors(crypto: Crypto): JsonArray = buildJsonArray {
    val a = fixedActor(crypto, 300, "Owner Phone")
    val impostor = fixedActor(crypto, 400, "Impostor Phone")
    val room = ByteArray(32) { (it + 60).toByte() }
    val nonce = ByteArray(24) { (it + 70).toByte() } // fixed: vectors must be reproducible, never crypto.randomBytes()
    val epochKeyA = ByteArray(32) { (it + 80).toByte() }
    val epochKeyB = ByteArray(32) { (it + 90).toByte() } // a different (wrong) key, for the reject case
    val body = OpBody.IdeaCreate(ByteArray(16) { (it + 100).toByte() }, "Camping trip", "long weekend", listOf("outdoors"))

    val valid = OpEnvelope.create(
        crypto = crypto, deviceSecretKey = a.deviceKey.secretKey, epochKey = epochKeyA,
        room = room, epoch = 1L, author = a.identity.userKey, device = a.deviceKey.publicKey,
        seq = 1L, lamport = 1L, body = body, nonce = nonce,
    )
    check(valid.verify(crypto)) { "generator bug: valid OpEnvelope vector does not verify" }
    val opened = valid.open(crypto, epochKeyA) { d -> if (d.contentEquals(a.deviceKey.publicKey)) a.cert else null }
    // OpBody's ByteArray fields make == reference equality, not content equality - compare
    // re-encoded canonical CBOR instead (deterministic, so equal bytes <=> equal content).
    check(opened is OpOpenResult.Ok && opened.body.encode().contentEquals(body.encode())) {
        "generator bug: valid OpEnvelope vector does not open to the expected body"
    }

    addJsonObject {
        put("name", "op-basic")
        putJsonObject("input") {
            put("room", room.b64())
            put("epoch", 1L)
            put("author", a.identity.userKey.b64())
            put("device", a.deviceKey.publicKey.b64())
            put("seq", 1L)
            put("lamport", 1L)
            put("nonce", nonce.b64())
            put("epochKey", epochKeyA.b64())
            putJsonObject("body") { put("type", "idea.create") }
        }
        putJsonObject("expected") {
            put("accept", true)
            put("ad", CanonicalCborCodec.encode(valid.toAdCbor()).b64())
            put("unsignedCbor", CanonicalCborCodec.encode(valid.toUnsignedCbor()).b64())
            put("signingInput", crypto.signingInput(OpEnvelope.DOMAIN, CanonicalCborCodec.encode(valid.toUnsignedCbor())).b64())
            put("sig", valid.sig!!.b64())
            put("cbor", CanonicalCborCodec.encode(valid.toFullCbor()).b64())
            put("opId", valid.opId(crypto).b64())
            put("plaintextCbor", body.encode().b64())
        }
    }

    val tamperedSig = valid.sig!!.copyOf().also { it[0] = it[0].inc() }
    addRejectOp(crypto, "op-reject-tampered-signature", valid.copy(sig = tamperedSig), epochKeyA, listOf(a.cert), "signature does not verify")

    // Wrong epoch key: this exact, validly-signed envelope, opened with a different key than it
    // was actually encrypted under.
    addRejectOp(crypto, "op-reject-wrong-epoch-key", valid, epochKeyB, listOf(a.cert), "AEAD authentication failed")

    // Tampered ad: the same ct (sealed under epoch=1's ad) spliced into an envelope that
    // otherwise, self-consistently, claims epoch=2 (and is validly re-signed for THAT claim) -
    // verify() alone can't catch this, since epoch is part of the signed content too and this
    // envelope's signature is perfectly self-consistent; only the AEAD step (which recomputes ad
    // from the envelope's *current* fields) catches the splice.
    val adTampered = OpEnvelope.sign(
        crypto, a.deviceKey.secretKey, room, epoch = 2L, a.identity.userKey, a.deviceKey.publicKey,
        seq = 1L, lamport = 1L, nonce = nonce, ct = valid.ct,
    )
    check(adTampered.verify(crypto)) { "generator bug: ad-splice OpEnvelope vector does not verify" }
    addRejectOp(crypto, "op-reject-tampered-ad", adTampered, epochKeyA, listOf(a.cert), "AEAD authentication failed")

    // Device not certified for author: signed validly by impostor's own device, but claims to be
    // authored by `a`.
    val impostorOp = OpEnvelope.create(
        crypto = crypto, deviceSecretKey = impostor.deviceKey.secretKey, epochKey = epochKeyA,
        room = room, epoch = 1L, author = a.identity.userKey, device = impostor.deviceKey.publicKey,
        seq = 1L, lamport = 1L, body = body, nonce = nonce,
    )
    addRejectOp(crypto, "op-reject-device-not-certified", impostorOp, epochKeyA, listOf(a.cert, impostor.cert), "device not certified for author")
}

private fun JsonArrayBuilder.addRejectOp(crypto: Crypto, name: String, op: OpEnvelope, epochKey: ByteArray, certs: List<DeviceCert>, reason: String) {
    val certOf: (ByteArray) -> DeviceCert? = { device -> certs.firstOrNull { it.device.contentEquals(device) } }
    val result = op.open(crypto, epochKey, certOf)
    check(result is OpOpenResult.Reject) { "generator bug: reject OpEnvelope vector '$name' opened successfully, want reject" }
    check(result.reason == reason) { "generator bug: reject OpEnvelope vector '$name' got reason '${result.reason}', want '$reason'" }
    addJsonObject {
        put("name", name)
        putJsonObject("input") {
            put("cbor", CanonicalCborCodec.encode(op.toFullCbor()).b64())
            put("epochKey", epochKey.b64())
            putJsonArray("certs") { certs.forEach { add(CanonicalCborCodec.encode(it.toFullCbor()).b64()) } }
        }
        putJsonObject("expected") {
            put("accept", false)
            put("reason", reason)
        }
    }
}
