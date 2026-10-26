package org.squaddle.core.sync

import io.ktor.client.HttpClient
import io.ktor.client.engine.js.Js
import io.ktor.client.plugins.websocket.WebSockets
import kotlin.js.Date

public actual fun createHttpClient(): HttpClient = HttpClient(Js) { install(WebSockets) }

public actual fun nowUnixSeconds(): Long = (Date().getTime() / 1000.0).toLong()
