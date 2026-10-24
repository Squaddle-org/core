package org.squaddle.core.encoding

/**
 * Deterministic CBOR (RFC 8949 §4.2.1): shortest-form ints, definite lengths,
 * map keys sorted by encoded bytes. Everything that is hashed or signed goes through here.
 *
 * TODO(M0): verify whether kotlinx-serialization-cbor produces deterministic output for our
 * integer-keyed maps. If not, implement a minimal encoder here (uint, bytes, tstr, array, map, bool, null).
 */
public interface CanonicalCbor {
    public fun encode(value: CborValue): ByteArray
    public fun decode(bytes: ByteArray): CborValue
}

public sealed interface CborValue {
    public data class UInt(val value: Long) : CborValue
    public data class NInt(val value: Long) : CborValue
    public class Bytes(public val value: ByteArray) : CborValue
    public data class Text(val value: String) : CborValue
    public data class Array(val items: List<CborValue>) : CborValue
    public data class Map(val entries: kotlin.collections.Map<Long, CborValue>) : CborValue
    public data class Bool(val value: Boolean) : CborValue
    public data object Null : CborValue
}
