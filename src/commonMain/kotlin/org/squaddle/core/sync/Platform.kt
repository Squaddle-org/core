package org.squaddle.core.sync

import io.ktor.client.HttpClient

/** Platform HTTP engine - OkHttp on both JVM and Android (the same engine artifact supports
 * both, so the two platform `actual`s are identical in substance, just separate files per KMP's
 * one-actual-per-target rule). */
public expect fun createHttpClient(): HttpClient

/** Unix seconds, for signing request-auth timestamps (PROTOCOL.md §5) - no clock in common stdlib. */
public expect fun nowUnixSeconds(): Long
