@file:OptIn(ExperimentalJsExport::class)

package org.squaddle.core.jsapi

import org.squaddle.core.backup.BackupRoomRef
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.crypto.LibsodiumCrypto
import org.squaddle.core.encoding.Base32
import org.squaddle.core.link.DeviceLink
import org.squaddle.core.link.LinkQr

/** [uri] is the full `squaddle-link:v1:...` string ({@link LinkQr.toUri}) - callers encode this
 * into a QR image (slave/N role) or get it from decoding a scanned camera frame (master/E role). */
@JsExport
public class LinkQrJs(public val uri: String, public val relayHost: String, public val code: ByteArray, public val ephemeralPublicKey: ByteArray)

@JsExport
public class GeneratedLinkJs(public val qr: LinkQrJs, public val ephemeralSecretKey: ByteArray)

@JsExport
public class LinkedIdentityJs(public val entropy: ByteArray, public val userKey: ByteArray, public val rooms: Array<BackupRoomRefJs>)

private fun LinkQr.toJs(): LinkQrJs = LinkQrJs(toUri(), relayHost, code, ephemeralPublicKey)

private fun BackupRoomRefJs.toCore(): BackupRoomRef = BackupRoomRef(Base32.encode(roomId) + "@" + relayHost, name)

/** `null` if [this] doesn't parse as `base32(roomId)@relayHost` - mirrors `BackupApi`'s own
 * room-ref round trip exactly (same wire shape, §2.3 reuses §7's). */
private fun BackupRoomRef.toJsOrNull(): BackupRoomRefJs? {
    val atIndex = roomRef.lastIndexOf('@')
    if (atIndex <= 0 || atIndex == roomRef.length - 1) return null
    val roomId = Base32.decode(roomRef.substring(0, atIndex)) ?: return null
    return BackupRoomRefJs(roomId, roomRef.substring(atIndex + 1), name)
}

/**
 * Thin `@JsExport` wrapper over [DeviceLink] (PROTOCOL.md §2.3) - same split as
 * [BackupApi]/[org.squaddle.core.backup.Backup]. A fresh [LibsodiumCrypto]/[createHttpClient] per
 * call is fine here (unlike [RelaySession], there's no session object to hold one across calls on
 * the slave/N side - it has no identity until linking finishes, so nothing to scope an instance to).
 */
@JsExport
public object LinkApi {
    public suspend fun generate(relayHost: String): GeneratedLinkJs {
        val crypto = LibsodiumCrypto.create()
        val generated = DeviceLink.generate(crypto, relayHost)
        return GeneratedLinkJs(generated.qr.toJs(), generated.ephemeralSecretKey)
    }

    /** `null` if [uri] doesn't parse as a `squaddle-link:v1:...` string. */
    public fun parseQr(uri: String): LinkQrJs? = LinkQr.parse(uri)?.toJs()

    public suspend fun sealForLink(qr: LinkQrJs, entropy: ByteArray, rooms: Array<BackupRoomRefJs>): ByteArray {
        val crypto = LibsodiumCrypto.create()
        val linkQr = LinkQr(qr.relayHost, qr.code, qr.ephemeralPublicKey)
        return DeviceLink.sealForLink(crypto, linkQr, entropy, rooms.map { it.toCore() })
    }

    /** `null` if [sealedBlob] doesn't open under this ephemeral keypair or isn't the expected
     * shape - see [DeviceLink.openLinkedIdentity]'s own doc comment. */
    public suspend fun openLinkedIdentity(ephemeralPublicKey: ByteArray, ephemeralSecretKey: ByteArray, sealedBlob: ByteArray): LinkedIdentityJs? {
        val crypto = LibsodiumCrypto.create()
        val identity = DeviceLink.openLinkedIdentity(crypto, KeyPair(ephemeralPublicKey, ephemeralSecretKey), sealedBlob) ?: return null
        val roomsJs = identity.rooms.mapNotNull { it.toJsOrNull() }.toTypedArray()
        return LinkedIdentityJs(identity.entropy, identity.userKey, roomsJs)
    }

    public suspend fun confirmationCode(ephemeralPublicKey: ByteArray, userKey: ByteArray): String {
        val crypto = LibsodiumCrypto.create()
        return DeviceLink.confirmationCode(crypto, ephemeralPublicKey, userKey)
    }

    public suspend fun postMailbox(relayHost: String, code: ByteArray, blob: ByteArray, tls: Boolean = true): Boolean =
        DeviceLink.postMailbox(relayHost, code, blob, tls)

    /** One GET; the caller (webclient's own poll loop) decides the retry cadence. */
    public suspend fun pollMailbox(relayHost: String, code: ByteArray, tls: Boolean = true): ByteArray? =
        DeviceLink.pollMailbox(relayHost, code, tls)
}
