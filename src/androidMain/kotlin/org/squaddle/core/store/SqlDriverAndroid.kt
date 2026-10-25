package org.squaddle.core.store

import android.content.Context
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.android.AndroidSqliteDriver

/**
 * [AndroidSqliteDriver] needs an application [Context], which [createSqlDriver]'s
 * platform-agnostic `expect` signature (shared with the JVM actual, which needs no such thing)
 * has no room for. M4 (the Android app, not yet built) is responsible for setting
 * [applicationContext] once at process startup (e.g. `Application.onCreate`) before any
 * [createSqlDriver] call on this platform - same "compile-checked now, wired for real once there
 * is an app to wire it from" discipline M0 already used for the libsodium Android bindings.
 */
public object AndroidSqlDriverContext {
    public lateinit var applicationContext: Context
}

public actual fun createSqlDriver(name: String): SqlDriver =
    AndroidSqliteDriver(SquaddleDb.Schema, AndroidSqlDriverContext.applicationContext, name)
