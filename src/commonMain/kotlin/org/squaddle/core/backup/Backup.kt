package org.squaddle.core.backup

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue

/** PROTOCOL.md §3.1: `RoomRef = base32(roomId) "@" relayHost`. [name] is the locally-chosen
 * display name for the room, if the user set one - purely a backup convenience, never signed or
 * sent anywhere else. */
public data class BackupRoomRef(public val roomRef: String, public val name: String? = null)

/** The plaintext PROTOCOL.md §7 encrypts: `{0:entropy, 1:rooms[...], 2:createdAt}`. */
public data class BackupContent(public val entropy: ByteArray, public val rooms: List<BackupRoomRef>, public val createdAt: Long)

/** `opsLimit`/`memLimit` are libsodium's `crypto_pwhash` tuning knobs - PROTOCOL.md §7 only names
 * the KDF ("argon2id13"), not fixed parameters, since a backup file is meant to stay crackable-
 * resistant for however long the real-world device doing the one-time encryption can tolerate. */
public data class Argon2Params(public val opsLimit: Long, public val memLimit: Int)

/**
 * PROTOCOL.md §7 `.squaddle-backup` file: `Backup {0:v=1, 1:kdf{0:"argon2id13",1:opslimit,
 * 2:memlimit,3:salt(16B)}, 2:nonce, 3:ct}`, `ct = AEAD(pwhash(passphrase), nonce, CBOR{0:entropy,
 * 1:rooms[{0:roomRef,1:name?}], 2:createdAt}, ad="squaddle-backup-v1")`. Not signed (there's no
 * device/user key involved at all - only a passphrase the user chooses), so there's no `verify`
 * here the way every other structure in this codebase has one; [restore] folds "does it parse"
 * and "does it decrypt" into a single nullable result instead.
 */
public object Backup {
    public const val AD: String = "squaddle-backup-v1"
    private const val NONCE_LENGTH = 24
    public const val SALT_LENGTH: Int = 16

    /** [salt]/[nonce] default to fresh random bytes; the overrides exist only so test-vector
     * generation can produce reproducible file bytes - production callers MUST NOT pass fixed
     * values for either. */
    public fun create(
        crypto: Crypto,
        passphrase: ByteArray,
        content: BackupContent,
        params: Argon2Params,
        salt: ByteArray = crypto.randomBytes(SALT_LENGTH),
        nonce: ByteArray = crypto.randomBytes(NONCE_LENGTH),
    ): ByteArray {
        val key = crypto.argon2id(passphrase, salt, params.opsLimit, params.memLimit)
        val plaintext = CanonicalCborCodec.encode(content.toCbor())
        val ct = crypto.aeadEncrypt(key, nonce, plaintext, AD.encodeToByteArray())
        val top = CborValue.Map(
            mapOf(
                0L to CborValue.UInt(1L),
                1L to CborValue.Map(
                    mapOf(
                        0L to CborValue.Text("argon2id13"),
                        1L to CborValue.UInt(params.opsLimit),
                        2L to CborValue.UInt(params.memLimit.toLong()),
                        3L to CborValue.Bytes(salt),
                    ),
                ),
                2L to CborValue.Bytes(nonce),
                3L to CborValue.Bytes(ct),
            ),
        )
        return CanonicalCborCodec.encode(top)
    }

    /** `null` on a malformed file, an unsupported KDF/version, or a wrong [passphrase] (AEAD
     * authentication failure) - never throws, deliberately indistinguishable from "wrong
     * passphrase" vs "corrupt file" to callers, same as every other AEAD-gated open in this
     * codebase. */
    public fun restore(crypto: Crypto, passphrase: ByteArray, fileBytes: ByteArray): BackupContent? {
        val top = try {
            (CanonicalCborCodec.decode(fileBytes) as? CborValue.Map)?.entries ?: return null
        } catch (e: CborFormatException) {
            return null
        }
        return try {
            if ((top.getValue(0L) as CborValue.UInt).value != 1L) return null
            val kdf = (top.getValue(1L) as CborValue.Map).entries
            if ((kdf.getValue(0L) as CborValue.Text).value != "argon2id13") return null
            val opsLimit = (kdf.getValue(1L) as CborValue.UInt).value
            val memLimit = (kdf.getValue(2L) as CborValue.UInt).value.toInt()
            val salt = (kdf.getValue(3L) as CborValue.Bytes).value
            val nonce = (top.getValue(2L) as CborValue.Bytes).value
            val ct = (top.getValue(3L) as CborValue.Bytes).value

            val key = crypto.argon2id(passphrase, salt, opsLimit, memLimit)
            val plaintext = crypto.aeadDecrypt(key, nonce, ct, AD.encodeToByteArray()) ?: return null
            decodeContent(plaintext)
        } catch (e: NoSuchElementException) {
            null
        } catch (e: ClassCastException) {
            null
        }
    }

    private fun BackupContent.toCbor(): CborValue = CborValue.Map(
        mapOf(
            0L to CborValue.Bytes(entropy),
            1L to CborValue.Array(
                rooms.map { room ->
                    CborValue.Map(
                        buildMap {
                            put(0L, CborValue.Text(room.roomRef))
                            room.name?.let { put(1L, CborValue.Text(it)) }
                        },
                    )
                },
            ),
            2L to CborValue.UInt(createdAt),
        ),
    )

    private fun decodeContent(bytes: ByteArray): BackupContent? {
        val m = try {
            (CanonicalCborCodec.decode(bytes) as? CborValue.Map)?.entries ?: return null
        } catch (e: CborFormatException) {
            return null
        }
        return try {
            val entropy = (m.getValue(0L) as CborValue.Bytes).value
            val rooms = (m.getValue(1L) as CborValue.Array).items.map { item ->
                val rm = (item as CborValue.Map).entries
                BackupRoomRef((rm.getValue(0L) as CborValue.Text).value, (rm[1L] as? CborValue.Text)?.value)
            }
            val createdAt = (m.getValue(2L) as CborValue.UInt).value
            BackupContent(entropy, rooms, createdAt)
        } catch (e: NoSuchElementException) {
            null
        } catch (e: ClassCastException) {
            null
        }
    }
}
