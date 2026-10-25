package org.squaddle.core.store

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import java.io.File

/** [name] `":memory:"` for an ephemeral in-memory database (tests, the CLI harness's own quick
 * runs); otherwise a file path. Schema is created on first use - detected by either being
 * in-memory or the file not existing yet, never re-run against an existing on-disk database. */
public actual fun createSqlDriver(name: String): SqlDriver {
    val isMemory = name == ":memory:"
    val needsSchema = isMemory || !File(name).exists()
    val url = if (isMemory) JdbcSqliteDriver.IN_MEMORY else "jdbc:sqlite:$name"
    val driver = JdbcSqliteDriver(url)
    if (needsSchema) {
        SquaddleDb.Schema.create(driver)
    }
    return driver
}
