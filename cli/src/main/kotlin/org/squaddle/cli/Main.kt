@file:OptIn(ExperimentalEncodingApi::class)

package org.squaddle.cli

import kotlinx.coroutines.runBlocking
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.encoding.Base32
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.EpochKeys
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipStateImpl
import org.squaddle.core.membership.StoredEntry
import org.squaddle.core.membership.roomId
import org.squaddle.core.ops.MembershipHistory
import org.squaddle.core.ops.OpBody
import org.squaddle.core.ops.OpOpenResult
import org.squaddle.core.ops.RoomState
import org.squaddle.core.store.LocalStore
import org.squaddle.core.store.createSqlDriver
import org.squaddle.core.sync.PushOutcome
import org.squaddle.core.sync.SyncClient
import java.io.File
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.system.exitProcess

/**
 * JVM CLI harness (ROADMAP.md M3) - manual smoke-test tool, driving `core`'s real APIs (no
 * reimplementation of any protocol logic here) against a real relay. One `-data-dir` is one
 * local device identity; room membership/sync state lives in `<data-dir>/squaddle.db` via the
 * same [LocalStore]/[SyncClient] a real app would use.
 */
fun main(rawArgs: Array<String>) {
    if (rawArgs.size < 2) {
        printUsageAndExit()
    }
    val (flags, positional) = parseFlags(rawArgs.drop(2))
    val dataDir = File(flags["data-dir"] ?: run { System.err.println("missing -data-dir"); exitProcess(2) })
    val relay = flags["relay"]

    runBlocking {
        val crypto = LibsodiumCrypto.create()
        when ("${rawArgs[0]} ${rawArgs[1]}") {
            "identity create" -> cmdIdentityCreate(crypto, dataDir, flags["label"] ?: "cli")
            "room create" -> cmdRoomCreate(crypto, dataDir, requireRelay(relay), positional.single())
            "room invite" -> cmdRoomInvite(crypto, dataDir, requireRelay(relay), positional.single(), flags["approval"] == "true")
            "room join" -> cmdRoomJoin(crypto, dataDir, positional.single())
            "room state" -> cmdRoomState(crypto, dataDir, requireRelay(relay), positional.single())
            "idea add" -> cmdIdeaAdd(crypto, dataDir, requireRelay(relay), positional[0], positional[1])
            "idea vote" -> cmdIdeaVote(crypto, dataDir, requireRelay(relay), positional[0], positional[1], positional[2].toInt())
            "idea comment" -> cmdIdeaComment(crypto, dataDir, requireRelay(relay), positional[0], positional[1], positional[2])
            "event create" -> cmdEventCreate(
                crypto, dataDir, requireRelay(relay), positional[0], positional[1], positional[2], positional[3].toLong(),
                flags["all-day"] == "true", flags["location"],
            )
            "event rsvp" -> cmdEventRsvp(crypto, dataDir, requireRelay(relay), positional[0], positional[1], positional[2])
            "member kick" -> cmdMemberKick(crypto, dataDir, requireRelay(relay), positional[0], positional[1])
            "member approve" -> cmdMemberApprove(crypto, dataDir, requireRelay(relay), positional[0], positional[1])
            "member promote" -> cmdMemberSetRole(crypto, dataDir, requireRelay(relay), positional[0], positional[1], "admin")
            "member demote" -> cmdMemberSetRole(crypto, dataDir, requireRelay(relay), positional[0], positional[1], "member")
            "member transfer" -> cmdMemberTransfer(crypto, dataDir, requireRelay(relay), positional[0], positional[1])
            "member list" -> cmdMemberList(crypto, dataDir, requireRelay(relay), positional[0])
            else -> printUsageAndExit()
        }
    }
    // OkHttp's dispatcher keeps non-daemon worker threads alive for its ~60s idle keep-alive
    // timeout, which would otherwise make every invocation of this short-lived CLI hang for a
    // minute after printing its result - force immediate exit instead.
    exitProcess(0)
}

private fun requireRelay(relay: String?): String = relay ?: run { System.err.println("missing -relay"); exitProcess(2) }

private fun parseFlags(args: List<String>): Pair<Map<String, String>, List<String>> {
    val flags = mutableMapOf<String, String>()
    val positional = mutableListOf<String>()
    var i = 0
    while (i < args.size) {
        val a = args[i]
        if (a.startsWith("-")) {
            flags[a.removePrefix("-")] = args.getOrElse(i + 1) { "" }
            i += 2
        } else {
            positional += a
            i += 1
        }
    }
    return flags to positional
}

private fun printUsageAndExit(): Nothing {
    System.err.println(
        """
        Usage: squaddle-cli <subcommand> -data-dir <dir> [-relay <host>] [args...]

          identity create [-label <text>]
          room create -relay <host> <roomName>
          room invite -relay <host> <roomRef> [-approval true|false]
          room join <inviteLink>
          room state -relay <host> <roomRef>
          idea add -relay <host> <roomRef> <title>
          idea vote -relay <host> <roomRef> <ideaIdHex> <value>
          idea comment -relay <host> <roomRef> <ideaIdHex> <text>
          event create -relay <host> <roomRef> <ideaIdHex|-> <title> <startUnix> [-all-day true] [-location <text>]
          event rsvp -relay <host> <roomRef> <eventIdHex> <yes|no|maybe>
          member kick -relay <host> <roomRef> <userKeyB64>
          member approve -relay <host> <roomRef> <userKeyB64>
          member promote -relay <host> <roomRef> <userKeyB64>   (-> admin)
          member demote -relay <host> <roomRef> <userKeyB64>    (-> member)
          member transfer -relay <host> <roomRef> <userKeyB64>  (owner only, target must be admin)
          member list -relay <host> <roomRef>
        """.trimIndent(),
    )
    exitProcess(2)
}

// ---- persistence: one identity + device per -data-dir, deterministic (Ed25519 signing is
// deterministic - see DeviceCertTest/LogEntryTest), so nothing but the seeds + label/issuedAt
// need to be on disk; room metadata lives one text file per room under rooms/. ----

private fun b64(bytes: ByteArray): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
private fun unb64(s: String): ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(s)
private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
private fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

private class CliIdentity(val userIdentity: UserIdentity, val device: org.squaddle.core.crypto.KeyPair, val cert: DeviceCert)

private fun identityFile(dataDir: File) = File(dataDir, "identity.txt")

private suspend fun loadIdentity(crypto: Crypto, dataDir: File): CliIdentity {
    val f = identityFile(dataDir)
    if (!f.exists()) {
        System.err.println("no identity at ${dataDir.path} - run `identity create -data-dir ${dataDir.path}` first")
        exitProcess(2)
    }
    val fields = f.readLines().filter { it.isNotBlank() }.associate {
        val (k, v) = it.split("=", limit = 2)
        k to v
    }
    val entropy = unb64(fields.getValue("entropy"))
    val deviceSeed = unb64(fields.getValue("deviceSeed"))
    val label = fields.getValue("label")
    val issuedAt = fields.getValue("issuedAt").toLong()

    val userIdentity = UserIdentity.fromEntropy(crypto, entropy)
    val device = crypto.signSeedKeypair(deviceSeed)
    val cert = DeviceCert.sign(crypto, userIdentity.signing.secretKey, userIdentity.userKey, userIdentity.userBoxKey, device.publicKey, label, issuedAt)
    return CliIdentity(userIdentity, device, cert)
}

private fun cmdIdentityCreate(crypto: Crypto, dataDir: File, label: String) {
    dataDir.mkdirs()
    if (identityFile(dataDir).exists()) {
        System.err.println("identity already exists at ${dataDir.path}")
        exitProcess(1)
    }
    val entropy = crypto.randomBytes(32)
    val deviceSeed = crypto.randomBytes(32)
    val issuedAt = System.currentTimeMillis() / 1000
    identityFile(dataDir).writeText("entropy=${b64(entropy)}\ndeviceSeed=${b64(deviceSeed)}\nlabel=$label\nissuedAt=$issuedAt\n")

    val identity = UserIdentity.fromEntropy(crypto, entropy)
    println("identity created at ${dataDir.path}")
    println("userKey: ${b64(identity.userKey)}")
    println("mnemonic (back this up, never share it): ${identity.toMnemonic(crypto).joinToString(" ")}")
}

// ---- rooms: one text file per room under rooms/, keyed by RoomRef, storing roomId+nonce+host ----

private fun roomRefOf(roomIdBytes: ByteArray, relayHost: String): String = "${Base32.encode(roomIdBytes)}@$relayHost"

private fun roomFile(dataDir: File, roomRef: String) = File(File(dataDir, "rooms"), roomRef.replace("/", "_") + ".txt")

private fun saveRoomMeta(dataDir: File, roomRef: String, roomIdBytes: ByteArray, nonce: ByteArray, relayHost: String) {
    val f = roomFile(dataDir, roomRef)
    f.parentFile.mkdirs()
    f.writeText("roomId=${b64(roomIdBytes)}\nnonce=${b64(nonce)}\nrelayHost=$relayHost\n")
}

private fun loadRoomMeta(dataDir: File, roomRef: String): Triple<ByteArray, ByteArray, String> {
    val f = roomFile(dataDir, roomRef)
    if (!f.exists()) {
        System.err.println("unknown room $roomRef in ${dataDir.path}")
        exitProcess(2)
    }
    val fields = f.readLines().filter { it.isNotBlank() }.associate {
        val (k, v) = it.split("=", limit = 2)
        k to v
    }
    return Triple(unb64(fields.getValue("roomId")), unb64(fields.getValue("nonce")), fields.getValue("relayHost"))
}

private fun openStore(dataDir: File): LocalStore {
    dataDir.mkdirs()
    return LocalStore(createSqlDriver(File(dataDir, "squaddle.db").path))
}

private suspend fun newSyncClient(crypto: Crypto, dataDir: File, relay: String): Triple<SyncClient, CliIdentity, LocalStore> {
    val identity = loadIdentity(crypto, dataDir)
    val store = openStore(dataDir)
    // tls=false by default: this CLI normally talks directly to the relay binary (plain HTTP,
    // see relay/cmd/relay/main.go) for local dev/manual testing. SQUADDLE_CLI_TLS=true switches
    // to https - a real deployed relay (always terminates TLS upstream) otherwise 308-redirects
    // plain HTTP and this CLI doesn't follow redirects. An env var rather than a new flag thread
    // through every cmdXxx function - this is a manual-testing nicety, not a protocol concern.
    val tls = System.getenv("SQUADDLE_CLI_TLS") == "true"
    val sync = SyncClient(crypto, store, relay, identity.userIdentity, identity.device, identity.cert, tls = tls)
    sync.publishDeviceCert()
    return Triple(sync, identity, store)
}

private fun exitOnFailure(outcome: PushOutcome) {
    if (outcome !is PushOutcome.Ok) {
        System.err.println("failed: $outcome")
        exitProcess(1)
    }
}

private suspend fun cmdRoomCreate(crypto: Crypto, dataDir: File, relay: String, name: String) {
    val (sync, identity, _) = newSyncClient(crypto, dataDir, relay)
    val nonce = crypto.randomBytes(16)
    val roomIdBytes = roomId(crypto, identity.userIdentity.userKey, nonce)
    exitOnFailure(sync.createRoom(roomIdBytes, nonce))
    val roomRef = roomRefOf(roomIdBytes, relay)
    saveRoomMeta(dataDir, roomRef, roomIdBytes, nonce, relay)
    println("room created: $roomRef ($name)")
}

private suspend fun cmdRoomInvite(crypto: Crypto, dataDir: File, relay: String, roomRef: String, requiresApproval: Boolean) {
    val (sync, _, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.rehydrateEpochKeys(roomIdBytes)
    val inviteId = crypto.randomBytes(16)
    exitOnFailure(sync.createInvite(roomIdBytes, inviteId, requiresApproval))
    if (!requiresApproval) {
        // createInvite() already generated+stored the secret - read it back to print the real link.
        val store = openStore(dataDir)
        val secret = store.inviteSecretsFor(roomIdBytes).first { it.invite_id.contentEquals(inviteId) }.secret
        println("invite link: https://squaddle.org/j/$relay/${Base32.encode(roomIdBytes)}/${Base32.encode(inviteId)}#${b64(secret)}")
    } else {
        println("invite created (requires approval): inviteId=${b64(inviteId)}")
    }
}

/** An **open** (no-approval) invite link carries `#<b64 inviteSecret>`; an **approval-required**
 * one has no fragment at all (`createInvite` never seals/uploads an envelope for it - §3.5, the
 * epoch key arrives later via the owner/admin's `approve` entry instead) - mirrors android's own
 * `RealSyncGateway.joinViaLink` exactly: with no secret, skip straight to `pullLog` + a plain
 * `JOIN` entry instead of `SyncClient.joinViaLink`'s envelope-fetch path. */
private suspend fun cmdRoomJoin(crypto: Crypto, dataDir: File, link: String) {
    // https://<linkHost>/j/<relayHost>/<b32 roomId>/<b32 inviteId>[#<b64 inviteSecret>]
    val afterJ = link.substringAfter("/j/")
    val hasSecret = afterJ.contains("#")
    val fragment = afterJ.substringAfter("#", missingDelimiterValue = "")
    val pathPart = afterJ.substringBefore("#")
    val parts = pathPart.split("/")
    require(parts.size == 3) { "malformed invite link: $link" }
    val relay = parts[0]
    val roomIdBytes = Base32.decode(parts[1]) ?: run { System.err.println("bad roomId in link"); exitProcess(2) }
    val inviteId = Base32.decode(parts[2]) ?: run { System.err.println("bad inviteId in link"); exitProcess(2) }

    val (sync, identity, _) = newSyncClient(crypto, dataDir, relay)
    val outcome = if (hasSecret) {
        sync.joinViaLink(roomIdBytes, inviteId, unb64(fragment))
    } else {
        val pullOutcome = sync.pullLog(roomIdBytes)
        if (pullOutcome is org.squaddle.core.sync.SyncOutcome.Error) {
            System.err.println("failed: $pullOutcome"); exitProcess(1)
        }
        sync.appendLogEntry(roomIdBytes) { index, prev ->
            LogEntry.sign(
                crypto, identity.device.secretKey, roomIdBytes, index, prev, identity.userIdentity.userKey, identity.cert,
                EntryType.JOIN, CborValue.Map(mapOf(0L to CborValue.Bytes(inviteId))), System.currentTimeMillis() / 1000,
            )
        }
    }
    exitOnFailure(outcome)
    val roomRef = roomRefOf(roomIdBytes, relay)
    saveRoomMeta(dataDir, roomRef, roomIdBytes, ByteArray(16), relay) // nonce unknown to a joiner - not needed again locally
    println(if (hasSecret) "joined $roomRef" else "joined $roomRef (pending approval)")
}

private fun certResolverFromLog(store: LocalStore, roomIdBytes: ByteArray): (ByteArray) -> DeviceCert? {
    val byDevice = mutableMapOf<String, DeviceCert>()
    for (row in store.logEntriesFrom(roomIdBytes, 0L)) {
        val entry = LogEntry.decode(row.entry_cbor) ?: continue
        byDevice[entry.cert.device.joinToString("") { "%02x".format(it) }] = entry.cert
    }
    return { device -> byDevice[device.joinToString("") { "%02x".format(it) }] }
}

private suspend fun materializeRoomState(crypto: Crypto, sync: SyncClient, store: LocalStore, roomIdBytes: ByteArray): RoomState {
    sync.pull(roomIdBytes)
    sync.rehydrateEpochKeys(roomIdBytes)

    val logRows = store.logEntriesFrom(roomIdBytes, 0L)
    var state = MembershipStateImpl.empty(crypto)
    val storedEntries = mutableListOf<StoredEntry>()
    for (row in logRows) {
        val entry = LogEntry.decode(row.entry_cbor) ?: continue
        val stored = StoredEntry(entry, row.rts)
        state = state.apply(stored).getOrElse { state }
        storedEntries += stored
    }
    val history = MembershipHistory.build(storedEntries, MembershipStateImpl.empty(crypto))

    val certOf = certResolverFromLog(store, roomIdBytes)
    val ops = store.opsAfter(roomIdBytes, 0L).mapNotNull { row ->
        val env = org.squaddle.core.ops.OpEnvelope.decode(row.envelope_cbor) ?: return@mapNotNull null
        val key = sync.epochKeyFor(roomIdBytes, env.epoch) ?: return@mapNotNull null
        val opened = env.open(crypto, key, certOf)
        (opened as? OpOpenResult.Ok)?.let { env to it.body }
    }
    return RoomState.fold(ops, history)
}

private suspend fun cmdRoomState(crypto: Crypto, dataDir: File, relay: String, roomRef: String) {
    val (sync, _, store) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    val state = materializeRoomState(crypto, sync, store, roomIdBytes)

    println("room $roomRef:")
    println("  ideas:")
    for (idea in state.ideas.values) {
        if (idea.deleted) continue
        println("    ${idea.id.joinToString("") { "%02x".format(it) }}  ${idea.title}")
    }
    println("  votes: ${state.votes.size}")
    println("  comments: ${state.comments.count { !it.value.deleted }}")
    println("  events: ${state.events.count { !it.value.cancelled }}")
}

private suspend fun cmdIdeaAdd(crypto: Crypto, dataDir: File, relay: String, roomRef: String, title: String) {
    val (sync, _, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    sync.rehydrateEpochKeys(roomIdBytes)
    val ideaId = crypto.randomBytes(16)
    check(sync.enqueueOp(roomIdBytes, OpBody.IdeaCreate(ideaId, title, null, emptyList()))) { "no epoch key available - pull first" }
    exitOnFailure(sync.push(roomIdBytes))
    println("idea added: ${ideaId.joinToString("") { "%02x".format(it) }}")
}

private suspend fun cmdIdeaVote(crypto: Crypto, dataDir: File, relay: String, roomRef: String, ideaIdHex: String, value: Int) {
    val (sync, _, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    sync.rehydrateEpochKeys(roomIdBytes)
    val ideaId = unhex(ideaIdHex)
    check(sync.enqueueOp(roomIdBytes, OpBody.VoteSet(ideaId, value))) { "no epoch key available - pull first" }
    exitOnFailure(sync.push(roomIdBytes))
    println("voted $value on $ideaIdHex")
}

private suspend fun cmdIdeaComment(crypto: Crypto, dataDir: File, relay: String, roomRef: String, ideaIdHex: String, text: String) {
    val (sync, _, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    sync.rehydrateEpochKeys(roomIdBytes)
    val ideaId = unhex(ideaIdHex)
    val commentId = crypto.randomBytes(16)
    check(sync.enqueueOp(roomIdBytes, OpBody.CommentAdd(commentId, ideaId, text))) { "no epoch key available - pull first" }
    exitOnFailure(sync.push(roomIdBytes))
    println("comment added: ${hex(commentId)}")
}

// tz is always "UTC" and end is always unset here - this is a manual-test harness, not a full
// client; both are free to add if a test flow ever actually needs them.
private suspend fun cmdEventCreate(
    crypto: Crypto,
    dataDir: File,
    relay: String,
    roomRef: String,
    ideaIdHexOrDash: String,
    title: String,
    startUnix: Long,
    allDay: Boolean,
    location: String?,
) {
    val (sync, _, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    sync.rehydrateEpochKeys(roomIdBytes)
    val ideaId = if (ideaIdHexOrDash == "-") null else unhex(ideaIdHexOrDash)
    val eventId = crypto.randomBytes(16)
    check(
        sync.enqueueOp(roomIdBytes, OpBody.EventCreate(eventId, ideaId, title, startUnix, null, "UTC", location, allDay)),
    ) { "no epoch key available - pull first" }
    exitOnFailure(sync.push(roomIdBytes))
    println("event created: ${hex(eventId)}")
}

private suspend fun cmdEventRsvp(crypto: Crypto, dataDir: File, relay: String, roomRef: String, eventIdHex: String, value: String) {
    require(value == "yes" || value == "no" || value == "maybe") { "rsvp value must be yes|no|maybe, got $value" }
    val (sync, _, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    sync.rehydrateEpochKeys(roomIdBytes)
    val eventId = unhex(eventIdHex)
    check(sync.enqueueOp(roomIdBytes, OpBody.RsvpSet(eventId, value))) { "no epoch key available - pull first" }
    exitOnFailure(sync.push(roomIdBytes))
    println("rsvp $value on $eventIdHex")
}

private suspend fun cmdMemberKick(crypto: Crypto, dataDir: File, relay: String, roomRef: String, userKeyB64: String) {
    val (sync, _, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    val target = unb64(userKeyB64)
    val identity = loadIdentity(crypto, dataDir)
    val outcome = sync.appendLogEntry(roomIdBytes) { index, prev ->
        LogEntry.sign(
            crypto, identity.device.secretKey, roomIdBytes, index, prev, identity.userIdentity.userKey, identity.cert,
            EntryType.REMOVE, CborValue.Map(mapOf(0L to CborValue.Bytes(target))), System.currentTimeMillis() / 1000,
        )
    }
    exitOnFailure(outcome)
    println("removed $userKeyB64 from $roomRef - epoch rotation owed (ADR-0012), next push auto-rotates")
}

/** Mirrors android's own `RealSyncGateway.buildHistory` (app/src/main/kotlin/org/squaddle/app/data/RealSyncGateway.kt). */
private fun membershipHistory(crypto: Crypto, store: LocalStore, roomIdBytes: ByteArray): MembershipHistory {
    var state: org.squaddle.core.membership.MembershipState = MembershipStateImpl.empty(crypto)
    val storedEntries = mutableListOf<StoredEntry>()
    for (row in store.logEntriesFrom(roomIdBytes, 0L)) {
        val entry = LogEntry.decode(row.entry_cbor) ?: continue
        val stored = StoredEntry(entry, row.rts)
        state = state.apply(stored).getOrElse { state }
        storedEntries += stored
    }
    return MembershipHistory.build(storedEntries, MembershipStateImpl.empty(crypto))
}

/** Mirrors android's own `RealSyncGateway.collectUserBoxKeys` - needed by [cmdMemberApprove] to seal
 * the current epoch key to the target's actual per-user box key (read off their own join entry). */
private fun userBoxKeyFor(store: LocalStore, roomIdBytes: ByteArray, target: ByteArray): ByteArray? {
    for (row in store.logEntriesFrom(roomIdBytes, 0L)) {
        val entry = LogEntry.decode(row.entry_cbor) ?: continue
        if (entry.author.contentEquals(target)) return entry.cert.userBox
    }
    return null
}

private suspend fun cmdMemberApprove(crypto: Crypto, dataDir: File, relay: String, roomRef: String, userKeyB64: String) {
    val (sync, identity, store) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    sync.rehydrateEpochKeys(roomIdBytes)
    val target = unb64(userKeyB64)
    val epoch = membershipHistory(crypto, store, roomIdBytes).current.epoch
    val epochKey = sync.epochKeyFor(roomIdBytes, epoch) ?: run { System.err.println("epoch key not available locally"); exitProcess(1) }
    val targetUserBox = userBoxKeyFor(store, roomIdBytes, target)
        ?: run { System.err.println("target's userBoxKey not found - have they sent a join entry yet?"); exitProcess(1) }
    val sealed = EpochKeys.seal(crypto, targetUserBox, roomIdBytes, epoch, epochKey)
    val outcome = sync.appendLogEntry(roomIdBytes) { index, prev ->
        LogEntry.sign(
            crypto, identity.device.secretKey, roomIdBytes, index, prev, identity.userIdentity.userKey, identity.cert,
            EntryType.APPROVE, CborValue.Map(mapOf(0L to CborValue.Bytes(target), 1L to CborValue.Bytes(sealed))), System.currentTimeMillis() / 1000,
        )
    }
    exitOnFailure(outcome)
    println("approved $userKeyB64 in $roomRef")
}

private suspend fun cmdMemberSetRole(crypto: Crypto, dataDir: File, relay: String, roomRef: String, userKeyB64: String, role: String) {
    val (sync, identity, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    val target = unb64(userKeyB64)
    val outcome = sync.appendLogEntry(roomIdBytes) { index, prev ->
        LogEntry.sign(
            crypto, identity.device.secretKey, roomIdBytes, index, prev, identity.userIdentity.userKey, identity.cert,
            EntryType.SET_ROLE, CborValue.Map(mapOf(0L to CborValue.Bytes(target), 1L to CborValue.Text(role))), System.currentTimeMillis() / 1000,
        )
    }
    exitOnFailure(outcome)
    println("set $userKeyB64 to $role in $roomRef")
}

private suspend fun cmdMemberTransfer(crypto: Crypto, dataDir: File, relay: String, roomRef: String, userKeyB64: String) {
    val (sync, identity, _) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    val target = unb64(userKeyB64)
    val outcome = sync.appendLogEntry(roomIdBytes) { index, prev ->
        LogEntry.sign(
            crypto, identity.device.secretKey, roomIdBytes, index, prev, identity.userIdentity.userKey, identity.cert,
            EntryType.TRANSFER_OWNER, CborValue.Map(mapOf(0L to CborValue.Bytes(target))), System.currentTimeMillis() / 1000,
        )
    }
    exitOnFailure(outcome)
    println("transferred ownership of $roomRef to $userKeyB64")
}

private suspend fun cmdMemberList(crypto: Crypto, dataDir: File, relay: String, roomRef: String) {
    val (sync, _, store) = newSyncClient(crypto, dataDir, relay)
    val (roomIdBytes, _, _) = loadRoomMeta(dataDir, roomRef)
    sync.pull(roomIdBytes)
    val history = membershipHistory(crypto, store, roomIdBytes)
    for (member in history.current.members()) {
        println("${b64(member.user)}  ${member.role}")
    }
}
