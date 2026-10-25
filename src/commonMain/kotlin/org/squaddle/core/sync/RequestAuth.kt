@file:OptIn(ExperimentalEncodingApi::class)

package org.squaddle.core.sync

import org.squaddle.core.crypto.Crypto
import org.squaddle.core.crypto.signingInput
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * PROTOCOL.md §5: the self-certifying request-auth header every write and member read needs.
 *
 * ```
 * Authorization: SQDL1 device=<b64>, ts=<unix>, sig=<b64>
 * ```
 * over `"SQDL1" ‖ "req" ‖ 0x00 ‖ BLAKE2b(method ‖ "\n" ‖ path+query ‖ "\n" ‖ ts ‖ "\n" ‖ BLAKE2b(body))`.
 *
 * This exact byte layout is read directly out of `relay/internal/api/auth.go` (not re-derived):
 * `reqLine := method + "\n" + r.URL.RequestURI() + "\n" + ts + "\n"`, then
 * `SigningInput("req", reqLine ‖ Blake2b256(body))` - which is exactly
 * [org.squaddle.core.crypto.signingInput]'s own `"SQDL1" ‖ domain ‖ 0x00 ‖ BLAKE2b(data)` formula
 * applied to `domain="req"`, `data = reqLine ‖ BLAKE2b(body)`. [pathAndQuery] must match Go's
 * `r.URL.RequestURI()` rendering exactly: the path, plus `?` and the query string if one is
 * present, nothing appended if it isn't (never a trailing bare `?`).
 */
public object RequestAuth {

    private fun b64(bytes: ByteArray): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)

    /** The raw signing input (domain "req") - exposed for vector generation; callers normally
     * want [headerValue] instead. */
    public fun signingInput(crypto: Crypto, method: String, pathAndQuery: String, tsUnix: Long, body: ByteArray): ByteArray {
        val reqLine = "$method\n$pathAndQuery\n$tsUnix\n".encodeToByteArray()
        return crypto.signingInput("req", reqLine + crypto.blake2b256(body))
    }

    /** Signs [body] (empty for a GET) and returns the full `Authorization` header value. */
    public fun headerValue(
        crypto: Crypto,
        deviceSecretKey: ByteArray,
        devicePublicKey: ByteArray,
        method: String,
        pathAndQuery: String,
        tsUnix: Long,
        body: ByteArray,
    ): String {
        val sig = crypto.sign(deviceSecretKey, signingInput(crypto, method, pathAndQuery, tsUnix, body))
        return "SQDL1 device=${b64(devicePublicKey)}, ts=$tsUnix, sig=${b64(sig)}"
    }
}
