@file:OptIn(ExperimentalJsExport::class)

package org.squaddle.core.jsapi

import org.squaddle.core.encoding.Base32

/** `@JsExport` wrapper over `org.squaddle.core.encoding.Base32` - invite links' `roomId`/
 * `inviteId` path segments (PROTOCOL.md §3.5) must stay interoperable with android's own links,
 * which use this same encoding; reimplementing it in TypeScript would risk silent divergence. */
@JsExport
public object EncodingApi {
    public fun base32Encode(bytes: ByteArray): String = Base32.encode(bytes)

    /** `null` on malformed input - never throws. */
    public fun base32Decode(text: String): ByteArray? = Base32.decode(text)
}
