@file:OptIn(ExperimentalEncodingApi::class)

package org.squaddle.core.link

import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import org.squaddle.core.backup.BackupRoomRef
import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.KeyPair
import org.squaddle.core.encoding.CanonicalCborCodec
import org.squaddle.core.encoding.CborFormatException
import org.squaddle.core.encoding.CborValue
import org.squaddle.core.identity.UserIdentity
import org.squaddle.core.sync.createHttpClient
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** `squaddle-link:v1:<relayHost>:<b64 code>:<b64 ek.pk>` (PROTOCOL.md §2.3 step 1). */
public data class LinkQr(public val relayHost: String, public val code: ByteArray, public val ephemeralPublicKey: ByteArray) {
    public fun toUri(): String = "squaddle-link:v1:$relayHost:${b64Url(code)}:${b64Url(ephemeralPublicKey)}"

    public companion object {
        private const val PREFIX = "squaddle-link:v1:"

        /** `null` on anything that doesn't parse cleanly - never throws. */
        public fun parse(uri: String): LinkQr? {
            if (!uri.startsWith(PREFIX)) return null
            val rest = uri.removePrefix(PREFIX)
            // relayHost itself never contains ':' beyond an optional port, so splitting from the
            // right for the two trailing b64 fields (code, ek.pk) is unambiguous either way -
            // taking the last two ':'-separated parts works whether or not the host has a port.
            val parts = rest.split(":")
            if (parts.size < 3) return null
            val ekPk = b64UrlDecode(parts.last()) ?: return null
            val code = b64UrlDecode(parts[parts.size - 2]) ?: return null
            val relayHost = parts.subList(0, parts.size - 2).joinToString(":")
            if (relayHost.isEmpty()) return null
            return LinkQr(relayHost, code, ekPk)
        }
    }
}

public data class GeneratedLink(public val qr: LinkQr, public val ephemeralSecretKey: ByteArray)

public data class LinkedIdentity(public val entropy: ByteArray, public val userKey: ByteArray, public val rooms: List<BackupRoomRef>)

private fun b64Url(bytes: ByteArray): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)

private fun b64UrlDecode(text: String): ByteArray? =
    try {
        Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(text)
    } catch (e: IllegalArgumentException) {
        null
    }

/**
 * PROTOCOL.md §2.3 device linking - shares an already-provisioned identity with a new device via
 * a QR code and a one-shot relay mailbox (`POST`/`GET /v1/link/{code}`, unauthenticated: the new
 * device has no identity to authenticate with yet). Same seal/open-a-CBOR-payload shape as
 * [org.squaddle.core.membership.EpochKeys], just sealed to a throwaway ephemeral X25519 key
 * instead of a member's own box key.
 */
public object DeviceLink {
    private const val CODE_LENGTH = 16

    /** New device (N), step 1 - pure, no network. */
    public fun generate(crypto: Crypto, relayHost: String): GeneratedLink {
        val ephemeral = crypto.boxSeedKeypair(crypto.randomBytes(32))
        val code = crypto.randomBytes(CODE_LENGTH)
        return GeneratedLink(LinkQr(relayHost, code, ephemeral.publicKey), ephemeral.secretKey)
    }

    /** Existing device (E), step 2's payload - pure. [rooms] is this device's own known-rooms
     * list, same [BackupRoomRef] shape the backup codec already uses (PROTOCOL.md §7, reused
     * here per §2.3's own doc comment). */
    public fun sealForLink(crypto: Crypto, qr: LinkQr, entropy: ByteArray, rooms: List<BackupRoomRef>): ByteArray {
        val plaintext = CanonicalCborCodec.encode(
            CborValue.Map(
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
                ),
            ),
        )
        return crypto.sealBox(qr.ephemeralPublicKey, plaintext)
    }

    /** New device (N), step 3 - pure. `null` if [sealedBlob] doesn't open under
     * [ephemeralKeyPair] or isn't the expected shape - never throws on bad input, same tolerance
     * as [org.squaddle.core.membership.EpochKeys.open]/[org.squaddle.core.backup.Backup.restore]. */
    public fun openLinkedIdentity(crypto: Crypto, ephemeralKeyPair: KeyPair, sealedBlob: ByteArray): LinkedIdentity? {
        val plaintext = crypto.openSealedBox(ephemeralKeyPair, sealedBlob) ?: return null
        val map = try {
            (CanonicalCborCodec.decode(plaintext) as? CborValue.Map)?.entries ?: return null
        } catch (e: CborFormatException) {
            return null
        }
        return try {
            val entropy = (map.getValue(0L) as CborValue.Bytes).value
            val rooms = (map.getValue(1L) as CborValue.Array).items.map { item ->
                val roomMap = (item as CborValue.Map).entries
                BackupRoomRef((roomMap.getValue(0L) as CborValue.Text).value, (roomMap[1L] as? CborValue.Text)?.value)
            }
            val userKey = UserIdentity.fromEntropy(crypto, entropy).userKey
            LinkedIdentity(entropy, userKey, rooms)
        } catch (e: NoSuchElementException) {
            null
        } catch (e: ClassCastException) {
            null
        }
    }

    /** Step 4, both sides - pure. "First 20 bits of BLAKE2b(ek.pk ‖ userKey)" reduced mod
     * 1,000,000 and zero-padded to exactly 6 digits (PROTOCOL.md §2.3 - 20 bits alone doesn't
     * guarantee 6 digits: its range, 0..1,048,575, is 7 digits ~4.6% of the time). */
    public fun confirmationCode(crypto: Crypto, ephemeralPublicKey: ByteArray, userKey: ByteArray): String {
        val hash = crypto.blake2b256(ephemeralPublicKey, userKey)
        val top20Bits = (((hash[0].toInt() and 0xff) shl 16) or ((hash[1].toInt() and 0xff) shl 8) or (hash[2].toInt() and 0xff)) ushr 4
        return (top20Bits % 1_000_000).toString().padStart(6, '0')
    }

    /** Existing device (E), step 2's network call - unauthenticated, no device/session needed.
     * Builds its own one-shot [io.ktor.client.HttpClient] (not taken as a parameter: ktor's
     * client types aren't part of `core`'s public API - `build.gradle.kts` depends on
     * `ktor-client-core` as `implementation`, not `api`, so a consumer like android can call
     * this function but can't itself reference an `HttpClient` type - confirmed directly, this
     * was first written taking one as a parameter and failed to compile from android for exactly
     * that reason). */
    public suspend fun postMailbox(relayHost: String, code: ByteArray, blob: ByteArray, tls: Boolean = true): Boolean {
        val scheme = if (tls) "https" else "http"
        val resp = createHttpClient().request("$scheme://$relayHost/v1/link/${b64Url(code)}") {
            method = HttpMethod.Post
            setBody(blob)
        }
        return resp.status == HttpStatusCode.NoContent
    }

    /** New device (N), step 3's network call - one GET; the caller polls on its own schedule
     * (this makes no assumption about polling cadence/backoff policy). `null` on `404`/any
     * non-`200` status, same "not there yet, not an error" tolerance the mailbox's 5-minute TTL
     * and single-read-deletes semantics expect callers to simply retry against. See
     * [postMailbox]'s own doc comment on why this builds its own [io.ktor.client.HttpClient]
     * rather than taking one as a parameter. */
    public suspend fun pollMailbox(relayHost: String, code: ByteArray, tls: Boolean = true): ByteArray? {
        val scheme = if (tls) "https" else "http"
        val resp = createHttpClient().request("$scheme://$relayHost/v1/link/${b64Url(code)}") { method = HttpMethod.Get }
        if (resp.status != HttpStatusCode.OK) return null
        return resp.bodyAsBytes()
    }
}
