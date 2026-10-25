package org.squaddle.core.sync

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.websocket.WebSockets

public actual fun createHttpClient(): HttpClient = HttpClient(OkHttp) { install(WebSockets) }

public actual fun nowUnixSeconds(): Long = System.currentTimeMillis() / 1000
