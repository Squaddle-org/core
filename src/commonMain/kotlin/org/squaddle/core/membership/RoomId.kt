package org.squaddle.core.membership

import org.squaddle.core.crypto.Crypto

/**
 * PROTOCOL.md §3.1. `roomId = BLAKE2b-256("SQDL1room" ‖ creatorUserKey ‖ roomNonce)`.
 * A plain hash, not a signature - domain separation here is just a fixed prefix string, not the
 * `Crypto.signingInput` construction (which is for signed structures).
 */
public fun roomId(crypto: Crypto, creatorUserKey: ByteArray, roomNonce: ByteArray): ByteArray =
    crypto.blake2b256("SQDL1room".encodeToByteArray(), creatorUserKey, roomNonce)
