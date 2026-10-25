package org.squaddle.core.sync

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp

public actual fun createHttpClient(): HttpClient = HttpClient(OkHttp)

public actual fun nowUnixSeconds(): Long = System.currentTimeMillis() / 1000
