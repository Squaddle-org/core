@file:OptIn(ExperimentalJsExport::class)

package org.squaddle.core.jsapi

import org.squaddle.core.backup.Argon2Params
import org.squaddle.core.backup.Backup
import org.squaddle.core.backup.BackupContent
import org.squaddle.core.backup.BackupRoomRef
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.encoding.Base32

/** [roomId]/[relayHost] are the parsed halves of PROTOCOL.md §3.1's `RoomRef = base32(roomId) "@"
 * relayHost` - [BackupApi] itself only ever sees the opaque wire string, same split android's own
 * `BackupCodec.kt` (`toBackupRoomRef`/`toRoomIdAndRelayHost`) already does. */
@JsExport
public class BackupRoomRefJs(public val roomId: ByteArray, public val relayHost: String, public val name: String?)

@JsExport
public class BackupContentJs(public val entropy: ByteArray, public val rooms: Array<BackupRoomRefJs>, public val createdAt: Double)

/**
 * Stateless wrapper over `commonMain`'s existing [Backup] codec (PROTOCOL.md §7, already the real
 * passphrase -> Argon2id -> AEAD implementation, with test vectors - no new crypto here). Uses the
 * same [PRODUCTION_PARAMS] android's `BackupCodec.kt` hardcodes, so a backup file created by one
 * client restores on the other.
 */
@JsExport
public object BackupApi {
    /** PROTOCOL.md §1's mandated floor (`OPSLIMIT_MODERATE`/`MEMLIMIT_MODERATE`) - same choice,
     * same reasoning, as android's `BackupCodec.PRODUCTION_PARAMS`. */
    private val PRODUCTION_PARAMS = Argon2Params(opsLimit = 3L, memLimit = 268_435_456)

    public suspend fun create(entropy: ByteArray, rooms: Array<BackupRoomRefJs>, createdAt: Double, passphrase: String): ByteArray {
        val crypto = LibsodiumCrypto.create()
        val backupRooms = rooms.map { BackupRoomRef(Base32.encode(it.roomId) + "@" + it.relayHost, it.name) }
        val content = BackupContent(entropy, backupRooms, createdAt.toLong())
        return Backup.create(crypto, passphrase.encodeToByteArray(), content, PRODUCTION_PARAMS)
    }

    /** `null` on a malformed file or a wrong [passphrase] - same indistinguishable-by-design
     * failure as [Backup.restore] itself. A room ref that doesn't parse as `base32@host` is
     * skipped, not fatal to the whole restore (mirrors android's `toRoomIdAndRelayHost`). */
    public suspend fun restore(passphrase: String, fileBytes: ByteArray): BackupContentJs? {
        val crypto = LibsodiumCrypto.create()
        val content = Backup.restore(crypto, passphrase.encodeToByteArray(), fileBytes) ?: return null
        val rooms = content.rooms.mapNotNull { ref ->
            val atIndex = ref.roomRef.lastIndexOf('@')
            if (atIndex <= 0 || atIndex == ref.roomRef.length - 1) return@mapNotNull null
            val roomId = Base32.decode(ref.roomRef.substring(0, atIndex)) ?: return@mapNotNull null
            BackupRoomRefJs(roomId, ref.roomRef.substring(atIndex + 1), ref.name)
        }.toTypedArray()
        return BackupContentJs(content.entropy, rooms, content.createdAt.toDouble())
    }
}
