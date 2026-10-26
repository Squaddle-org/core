package org.squaddle.core.store

import app.cash.sqldelight.db.SqlDriver

/** [name] is ignored - this is in-memory only for now (ADR-0009's acknowledged gap; see
 * [SqlJsDriver]'s own doc comment). [preloadSqlJsDriver] must have already completed. */
public actual fun createSqlDriver(name: String): SqlDriver {
    val driver = SqlJsDriver()
    SquaddleDb.Schema.create(driver)
    return driver
}
