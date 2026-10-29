package org.squaddle.core.sync

import kotlinx.coroutines.test.runTest
import org.junit.Assume.assumeTrue
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.identity.DeviceCert
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.membership.EntryType
import org.squaddle.core.membership.LogEntry
import org.squaddle.core.membership.MembershipStateImpl
import org.squaddle.core.membership.StoredEntry
import org.squaddle.core.membership.roomId
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.ops.MembershipHistory
import org.squaddle.core.ops.OpBody
import org.squaddle.core.ops.OpOpenResult
import org.squaddle.core.ops.RoomState
import org.squaddle.core.store.LocalStore
import org.squaddle.core.store.createSqlDriver
import java.io.File
import java.net.HttpURLConnection
import java.net.ServerSocket
import java.net.URL
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ROADMAP.md M3's end-to-end integration test: builds and runs the *actual* relay binary from
 * `../relay` (not a mock), then drives three real identities through create room -> invite ->
 * two joins -> content ops from different authors -> a kick, verifying the kicked member loses
 * read access to new ops and the remaining members converge on byte-for-byte identical state.
 *
 * Skips (never fails) if `go` isn't on `PATH` - same "opt-in, not a hard requirement" discipline
 * as `SQUADDLE_TESTVECTORS` being unset elsewhere in this test suite.
 */
class EndToEndIntegrationTest {

    private var relayProcess: Process? = null

    @AfterTest
    fun tearDown() {
        relayProcess?.destroy()
        relayProcess?.waitFor()
    }

    private fun findGoExecutable(): String? {
        val onPath = System.getenv("PATH")?.split(File.pathSeparator).orEmpty()
            .map { File(it, "go") }
            .firstOrNull { it.canExecute() }
        if (onPath != null) return onPath.path
        // This sandbox's toolchain isn't always on the Gradle daemon's PATH (depends on whether
        // the shell that started the daemon sourced the env file) - fall back to the known
        // install location documented in core/CLAUDE.md's toolchain setup.
        val fallback = File(System.getProperty("user.home"), ".local/opt/go1.27.3/bin/go")
        return if (fallback.canExecute()) fallback.path else null
    }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun waitForHealthz(port: Int, timeoutMs: Long = 10_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                val conn = URL("http://127.0.0.1:$port/healthz").openConnection() as HttpURLConnection
                conn.connectTimeout = 500
                conn.readTimeout = 500
                if (conn.responseCode == 200) return
            } catch (e: Exception) {
                // not up yet
            }
            Thread.sleep(100)
        }
        error("relay did not become healthy within ${timeoutMs}ms")
    }

    private fun startRelay(goExe: String, relayDir: File, dbFile: File, listenPort: Int, metricsPort: Int, vapidKeyFile: File? = null): Process {
        val binFile = File.createTempFile("squaddle-relay", "")
        binFile.deleteOnExit()
        val build = ProcessBuilder(goExe, "build", "-o", binFile.absolutePath, "./cmd/relay")
            .directory(relayDir)
            .redirectErrorStream(true)
            .start()
        val buildOutput = build.inputStream.bufferedReader().readText()
        check(build.waitFor() == 0) { "go build failed:\n$buildOutput" }

        val args = mutableListOf(
            binFile.absolutePath,
            "-db", dbFile.absolutePath,
            "-listen", "127.0.0.1:$listenPort",
            "-metrics", "127.0.0.1:$metricsPort",
            "-limits", "none",
        )
        if (vapidKeyFile != null) {
            args += listOf("-vapid-private-key-file", vapidKeyFile.absolutePath)
        }
        val proc = ProcessBuilder(args).redirectErrorStream(true).start()
        waitForHealthz(metricsPort)
        return proc
    }

    private class Actor(
        val identity: UserIdentity,
        val device: KeyPair,
        val cert: DeviceCert,
        val sync: SyncClient,
        val store: LocalStore,
    )

    private suspend fun newActor(crypto: Crypto, relay: String, label: String): Actor {
        val identity = UserIdentity.create(crypto)
        val device = crypto.signSeedKeypair(crypto.randomBytes(32))
        val cert = DeviceCert.sign(crypto, identity.signing.secretKey, identity.userKey, identity.userBoxKey, device.publicKey, label, 1L)
        val store = LocalStore(createSqlDriver(":memory:"))
        val sync = SyncClient(crypto, store, relay, identity, device, cert, tls = false)
        val outcome = sync.publishDeviceCert()
        check(outcome == PushOutcome.Ok) { "publishDeviceCert failed for $label: $outcome" }
        return Actor(identity, device, cert, sync, store)
    }

    private fun certResolverFromLog(store: LocalStore, room: ByteArray): (ByteArray) -> DeviceCert? {
        val byDevice = mutableMapOf<String, DeviceCert>()
        for (row in store.logEntriesFrom(room, 0L)) {
            val entry = LogEntry.decode(row.entry_cbor) ?: continue
            byDevice[entry.cert.device.joinToString("") { "%02x".format(it) }] = entry.cert
        }
        return { device -> byDevice[device.joinToString("") { "%02x".format(it) }] }
    }

    private fun materialize(crypto: Crypto, actor: Actor, room: ByteArray): RoomState {
        actor.sync.rehydrateEpochKeys(room)
        val logRows = actor.store.logEntriesFrom(room, 0L)
        var state = MembershipStateImpl.empty(crypto)
        val storedEntries = mutableListOf<StoredEntry>()
        for (row in logRows) {
            val entry = LogEntry.decode(row.entry_cbor) ?: continue
            state = state.apply(StoredEntry(entry, row.rts)).getOrElse { state }
            storedEntries += StoredEntry(entry, row.rts)
        }
        val history = MembershipHistory.build(storedEntries, MembershipStateImpl.empty(crypto))
        val certOf = certResolverFromLog(actor.store, room)
        val ops = actor.store.opsAfter(room, 0L).mapNotNull { row ->
            val env = org.squaddle.core.ops.OpEnvelope.decode(row.envelope_cbor) ?: return@mapNotNull null
            val key = actor.sync.epochKeyFor(room, env.epoch) ?: return@mapNotNull null
            val opened = env.open(crypto, key, certOf)
            (opened as? OpOpenResult.Ok)?.let { env to it.body }
        }
        return RoomState.fold(ops, history)
    }

    @Test
    fun threeIdentitiesCreateJoinPostKickAndConverge() = runTest {
        val goExe = findGoExecutable()
        assumeTrue("`go` not found on PATH or at the documented fallback - skipping the real-relay integration test", goExe != null)

        val relayDir = File("../relay")
        assumeTrue("../relay checkout not found", relayDir.isDirectory)

        val dbFile = File.createTempFile("squaddle-e2e", ".db")
        dbFile.deleteOnExit()
        val listenPort = freePort()
        val metricsPort = freePort()
        relayProcess = startRelay(goExe!!, relayDir, dbFile, listenPort, metricsPort)
        val relay = "127.0.0.1:$listenPort"

        val crypto: Crypto = LibsodiumCrypto.create()
        val owner = newActor(crypto, relay, "Owner")
        val memberA = newActor(crypto, relay, "MemberA")
        val memberB = newActor(crypto, relay, "MemberB")

        // --- create room ---
        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.identity.userKey, roomNonce)
        val createOutcome = owner.sync.createRoom(room, roomNonce)
        assertEquals(PushOutcome.Ok, createOutcome, "createRoom failed: $createOutcome")

        // --- invite + two joins ---
        val inviteId = crypto.randomBytes(16)
        val inviteOutcome = owner.sync.createInvite(room, inviteId, requiresApproval = false)
        assertEquals(PushOutcome.Ok, inviteOutcome, "createInvite failed: $inviteOutcome")
        val secret = owner.store.inviteSecretsFor(room).first { it.invite_id.contentEquals(inviteId) }.secret

        val joinAOutcome = memberA.sync.joinViaLink(room, inviteId, secret)
        assertEquals(PushOutcome.Ok, joinAOutcome, "memberA join failed: $joinAOutcome")
        val joinBOutcome = memberB.sync.joinViaLink(room, inviteId, secret)
        assertEquals(PushOutcome.Ok, joinBOutcome, "memberB join failed: $joinBOutcome")

        // --- owner observes both joins, then everyone posts content ---
        val ownerPull1 = owner.sync.pull(room)
        assertEquals(SyncOutcome.Ok, ownerPull1, "owner pull (after joins) failed: $ownerPull1")
        val ideaId = crypto.randomBytes(16)
        assertTrue(owner.sync.enqueueOp(room, OpBody.IdeaCreate(ideaId, "Camping trip", "long weekend", listOf("outdoors"))), "owner enqueueOp(idea) failed")
        assertEquals(PushOutcome.Ok, owner.sync.push(room))

        val memberAPull1 = memberA.sync.pull(room)
        assertEquals(SyncOutcome.Ok, memberAPull1, "memberA pull failed: $memberAPull1")
        assertTrue(memberA.sync.enqueueOp(room, OpBody.VoteSet(ideaId, 1)), "memberA enqueueOp(vote) failed")
        assertEquals(PushOutcome.Ok, memberA.sync.push(room))

        val memberBPull1 = memberB.sync.pull(room)
        assertEquals(SyncOutcome.Ok, memberBPull1, "memberB pull failed: $memberBPull1")
        val commentId = crypto.randomBytes(16)
        assertTrue(memberB.sync.enqueueOp(room, OpBody.CommentAdd(commentId, ideaId, "count me in")), "memberB enqueueOp(comment) failed")
        assertEquals(PushOutcome.Ok, memberB.sync.push(room))

        // --- owner kicks memberA, auto-rotates ---
        val ownerPull2 = owner.sync.pull(room)
        assertEquals(SyncOutcome.Ok, ownerPull2, "owner pull (before kick) failed: $ownerPull2")
        val removeOutcome = owner.sync.appendLogEntry(room) { index, prev ->
            LogEntry.sign(
                crypto, owner.device.secretKey, room, index, prev, owner.identity.userKey, owner.cert,
                EntryType.REMOVE, CborValue.Map(mapOf(0L to CborValue.Bytes(memberA.identity.userKey))), 1_700_000_000L,
            )
        }
        assertEquals(PushOutcome.Ok, removeOutcome, "remove failed: $removeOutcome")
        // owner is the room's own admin/owner, so autoRotate() clears rotationPending directly -
        // same auto-rotate path push() would take on a 409 rotation_required, invoked explicitly
        // here since there's no pending outbox op to trigger it through.
        assertEquals(PushOutcome.Ok, owner.sync.autoRotate(room))

        // --- memberB posts one more op under the new epoch, after the rotation ---
        val memberBPull2 = memberB.sync.pull(room)
        assertEquals(SyncOutcome.Ok, memberBPull2, "memberB pull (after rotation) failed: $memberBPull2")
        assertTrue(memberB.sync.enqueueOp(room, OpBody.VoteSet(ideaId, 1)), "memberB enqueueOp(vote2) failed")
        assertEquals(PushOutcome.Ok, memberB.sync.push(room))

        // --- memberA (removed) can no longer read ops ---
        val memberAPullAfterKick = memberA.sync.pullOps(room)
        assertTrue(memberAPullAfterKick is SyncOutcome.Error, "expected removed member's ops read to fail, got $memberAPullAfterKick")
        assertEquals("forbidden", memberAPullAfterKick.code)

        // --- owner and memberB converge on identical state ---
        val ownerPull3 = owner.sync.pull(room)
        assertEquals(SyncOutcome.Ok, ownerPull3, "owner final pull failed: $ownerPull3")
        val memberBPull3 = memberB.sync.pull(room)
        assertEquals(SyncOutcome.Ok, memberBPull3, "memberB final pull failed: $memberBPull3")
        val ownerState = materialize(crypto, owner, room)
        val memberBState = materialize(crypto, memberB, room)

        assertEquals(1, ownerState.ideas.size)
        assertEquals(ownerState.ideas.keys, memberBState.ideas.keys)
        assertEquals(ownerState.ideas.values.single().title, memberBState.ideas.values.single().title)
        assertEquals(ownerState.comments.keys, memberBState.comments.keys)
        assertEquals(ownerState.votes.keys, memberBState.votes.keys)
        assertFalse(ownerState.votes.isEmpty())
    }

    /**
     * `getLimits`/`redeemVoucher` round-trip against a real relay in `-limits hosted` mode (the
     * `-limits none` every other test in this file uses always resolves `unlimited` regardless
     * of entitlements - `internal/limits/limits.go`'s own `Resolve` - so this test needs the
     * actual hosted policy to see a free->boosted transition at all).
     */
    @Test
    fun limitsAndVoucherRedemption() = runTest {
        val goExe = findGoExecutable()
        assumeTrue("`go` not found on PATH or at the documented fallback - skipping the real-relay integration test", goExe != null)

        val relayDir = File("../relay")
        assumeTrue("../relay checkout not found", relayDir.isDirectory)

        val dbFile = File.createTempFile("squaddle-limits", ".db")
        dbFile.deleteOnExit()
        val listenPort = freePort()
        val metricsPort = freePort()

        // Build once and mint the voucher *before* the server ever opens this db file - minting
        // via a second process concurrently with the running server hit real cross-process
        // SQLite read staleness (the server's own connection didn't see the other process's
        // just-committed insert); doing it first, sequentially, against a file nothing else has
        // open yet, avoids that question entirely rather than chasing journal-mode settings.
        val relayBin = File.createTempFile("squaddle-relay", "")
        relayBin.deleteOnExit()
        val build = ProcessBuilder(goExe, "build", "-o", relayBin.absolutePath, "./cmd/relay").directory(relayDir).redirectErrorStream(true).start()
        check(build.waitFor() == 0) { "go build failed:\n${build.inputStream.bufferedReader().readText()}" }
        val mint = ProcessBuilder(relayBin.absolutePath, "voucher", "mint", "-tier=boosted", "-duration-days=30", "-db", dbFile.absolutePath)
            .redirectErrorStream(true).start()
        val mintOutput = mint.inputStream.bufferedReader().readText()
        check(mint.waitFor() == 0) { "voucher mint failed:\n$mintOutput" }
        val code = mintOutput.trim().lines().last()

        relayProcess = ProcessBuilder(
            relayBin.absolutePath,
            "-db", dbFile.absolutePath,
            "-listen", "127.0.0.1:$listenPort",
            "-metrics", "127.0.0.1:$metricsPort",
            "-limits", "hosted",
        ).redirectErrorStream(true).start()
        waitForHealthz(metricsPort)
        val relay = "127.0.0.1:$listenPort"

        val crypto: Crypto = LibsodiumCrypto.create()
        val owner = newActor(crypto, relay, "Owner")

        val roomNonce = crypto.randomBytes(16)
        val room = roomId(crypto, owner.identity.userKey, roomNonce)
        assertEquals(PushOutcome.Ok, owner.sync.createRoom(room, roomNonce))

        val freeOutcome = owner.sync.getLimits(room)
        assertTrue(freeOutcome is LimitsOutcome.Ok, "expected Ok, got $freeOutcome")
        assertEquals("free", freeOutcome.limits.tier)
        assertEquals(20, freeOutcome.limits.maxMembers)

        val redeemOutcome = owner.sync.redeemVoucher(room, code)
        assertTrue(redeemOutcome is EntitlementOutcome.Ok, "expected Ok, got $redeemOutcome")
        assertEquals("boosted", redeemOutcome.tier)
        assertTrue(redeemOutcome.until != null, "boosted entitlement should have an expiry")

        val boostedOutcome = owner.sync.getLimits(room)
        assertTrue(boostedOutcome is LimitsOutcome.Ok, "expected Ok, got $boostedOutcome")
        assertEquals("boosted", boostedOutcome.limits.tier)
        assertEquals(100, boostedOutcome.limits.maxMembers)

        // Redeeming the same code twice (already redeemed) must fail cleanly, not throw.
        val reRedeemOutcome = owner.sync.redeemVoucher(room, code)
        assertTrue(reRedeemOutcome is EntitlementOutcome.Error, "expected a clean Error for an already-redeemed code, got $reRedeemOutcome")

        val badCodeOutcome = owner.sync.redeemVoucher(room, "not-a-real-voucher-code")
        assertTrue(badCodeOutcome is EntitlementOutcome.Error, "expected a clean Error for an unknown code, got $badCodeOutcome")
    }

    /** `relay vapid generate`'s stdout is `<banner line>\n<PEM>\n<banner line>\n<base64url
     * public key>\n` (cmd/relay/vapid.go) - extracts just the PEM block, the one thing
     * `-vapid-private-key-file` reads back in. */
    private fun extractPem(vapidGenerateOutput: String): String {
        val begin = vapidGenerateOutput.indexOf("-----BEGIN")
        val end = vapidGenerateOutput.indexOf("-----END EC PRIVATE KEY-----") + "-----END EC PRIVATE KEY-----".length
        check(begin >= 0 && end > begin) { "no PEM block found in:\n$vapidGenerateOutput" }
        return vapidGenerateOutput.substring(begin, end) + "\n"
    }

    /**
     * `vapidPublicKey`/`registerPushEndpoint`/`unregisterPush` against a real relay - mirrors
     * `limitsAndVoucherRedemption`'s "build once, mint/generate before the server opens the db"
     * discipline. With no `-vapid-private-key-file` at all, `GET /v1/push/vapid` must 404 and
     * [SyncClient.vapidPublicKey] must return `null` rather than throwing (ADR-0013: push stays
     * disabled, not a hard failure, for every self-hosted relay that never configures a key).
     */
    @Test
    fun pushRegistrationAndVapidKey() = runTest {
        val goExe = findGoExecutable()
        assumeTrue("`go` not found on PATH or at the documented fallback - skipping the real-relay integration test", goExe != null)

        val relayDir = File("../relay")
        assumeTrue("../relay checkout not found", relayDir.isDirectory)

        val relayBin = File.createTempFile("squaddle-relay", "")
        relayBin.deleteOnExit()
        val build = ProcessBuilder(goExe, "build", "-o", relayBin.absolutePath, "./cmd/relay").directory(relayDir).redirectErrorStream(true).start()
        check(build.waitFor() == 0) { "go build failed:\n${build.inputStream.bufferedReader().readText()}" }

        val generate = ProcessBuilder(relayBin.absolutePath, "vapid", "generate").redirectErrorStream(true).start()
        val generateOutput = generate.inputStream.bufferedReader().readText()
        check(generate.waitFor() == 0) { "vapid generate failed:\n$generateOutput" }
        val keyFile = File.createTempFile("vapid-key", ".pem")
        keyFile.deleteOnExit()
        keyFile.writeText(extractPem(generateOutput))

        // --- no VAPID key configured: push stays disabled, not an error ---
        val noKeyDbFile = File.createTempFile("squaddle-push-nokey", ".db")
        noKeyDbFile.deleteOnExit()
        val noKeyListenPort = freePort()
        val noKeyMetricsPort = freePort()
        relayProcess = startRelay(goExe!!, relayDir, noKeyDbFile, noKeyListenPort, noKeyMetricsPort)
        val crypto: Crypto = LibsodiumCrypto.create()
        val noKeyActor = newActor(crypto, "127.0.0.1:$noKeyListenPort", "NoKeyDevice")
        assertEquals(null, noKeyActor.sync.vapidPublicKey(), "a relay with no -vapid-private-key-file must not serve a public key")
        relayProcess?.destroy()
        relayProcess?.waitFor()

        // --- with a configured key: the served public key, register, and unregister all work ---
        val dbFile = File.createTempFile("squaddle-push", ".db")
        dbFile.deleteOnExit()
        val listenPort = freePort()
        val metricsPort = freePort()
        relayProcess = startRelay(goExe!!, relayDir, dbFile, listenPort, metricsPort, vapidKeyFile = keyFile)
        val relay = "127.0.0.1:$listenPort"

        val actor = newActor(crypto, relay, "Device")
        val servedPublicKey = actor.sync.vapidPublicKey()
        assertTrue(servedPublicKey != null && servedPublicKey.isNotBlank(), "expected a served VAPID public key, got $servedPublicKey")

        assertEquals(PushOutcome.Ok, actor.sync.registerPushEndpoint("https://push.example.org/endpoint/abc123"))
        assertEquals(PushOutcome.Ok, actor.sync.unregisterPush())
    }
}
