package org.squaddle.core.identity

/** PROTOCOL.md §2.2. CBOR field numbers in comments — keep in sync with the spec. */
public data class DeviceCert(
    val v: Int = 1,              // 0
    val user: ByteArray,         // 1
    val userBox: ByteArray,      // 2
    val device: ByteArray,       // 3
    val label: String,           // 4
    val issuedAt: Long,          // 5
    val sig: ByteArray? = null,  // 6
) {
    public companion object { public const val DOMAIN: String = "devcert" }
}
// TODO(M0): sign()/verify() via encoding.CanonicalCbor + Crypto.signingInput(DOMAIN, ...)
