package org.squaddle.core.store

import app.cash.sqldelight.Query
import app.cash.sqldelight.Transacter
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlCursor
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlPreparedStatement

/**
 * A synchronous `SqlDriver` wrapping sql.js directly (ADR-0009: no official SqlDelight browser
 * driver is compatible with `commonMain`'s synchronous generated `SquaddleDb` queries - the only
 * one that exists, `web-worker-driver-js`, is async by construction and would need every
 * platform's generated query API switched to `generateAsync`, not just this one target's). In
 * memory only for now (ADR-0009's acknowledged gap - sql.js's own `export()`/re-`import()` would
 * be the next step for real IndexedDB-backed persistence, not done here).
 */
internal class SqlJsDriver : SqlDriver {
    private val db: dynamic = sqlJsNewDatabase(requireNotNull(sqlJsStatic) { "preloadSqlJsDriver() must be awaited before createSqlDriver()" })

    private var transaction: Transaction? = null
    private val listeners = mutableMapOf<String, MutableSet<Query.Listener>>()

    override fun execute(identifier: Int?, sql: String, parameters: Int, binders: (SqlPreparedStatement.() -> Unit)?): QueryResult<Long> {
        val stmt = sqlJsPrepare(db, sql)
        try {
            bind(stmt, parameters, binders)
            sqlJsStep(stmt)
            return QueryResult.Value(sqlJsGetRowsModified(db).toLong())
        } finally {
            sqlJsFree(stmt)
        }
    }

    override fun <R> executeQuery(
        identifier: Int?,
        sql: String,
        mapper: (SqlCursor) -> QueryResult<R>,
        parameters: Int,
        binders: (SqlPreparedStatement.() -> Unit)?,
    ): QueryResult<R> {
        val stmt = sqlJsPrepare(db, sql)
        try {
            bind(stmt, parameters, binders)
            return mapper(SqlJsCursor(stmt))
        } finally {
            sqlJsFree(stmt)
        }
    }

    private fun bind(stmt: dynamic, parameters: Int, binders: (SqlPreparedStatement.() -> Unit)?) {
        if (parameters == 0 || binders == null) return
        val bound = arrayOfNulls<Any?>(parameters)
        BoundStatement(bound).binders()
        sqlJsBind(stmt, bound)
    }

    override fun newTransaction(): QueryResult<Transacter.Transaction> {
        val enclosing = transaction
        val newTransaction = Transaction(enclosing)
        transaction = newTransaction
        if (enclosing == null) sqlJsRun(db, "BEGIN TRANSACTION")
        else sqlJsRun(db, "SAVEPOINT SP_${newTransaction.depth}")
        return QueryResult.Value(newTransaction)
    }

    override fun currentTransaction(): Transacter.Transaction? = transaction

    override fun addListener(vararg queryKeys: String, listener: Query.Listener) {
        for (key in queryKeys) listeners.getOrPut(key) { mutableSetOf() }.add(listener)
    }

    override fun removeListener(vararg queryKeys: String, listener: Query.Listener) {
        for (key in queryKeys) listeners[key]?.remove(listener)
    }

    override fun notifyListeners(vararg queryKeys: String) {
        val notified = mutableSetOf<Query.Listener>()
        for (key in queryKeys) listeners[key]?.let { notified.addAll(it) }
        for (l in notified) l.queryResultsChanged()
    }

    override fun close() = sqlJsClose(db)

    private inner class Transaction(private val enclosing: Transaction?) : Transacter.Transaction() {
        val depth: Int = (enclosing?.depth ?: 0) + 1

        override fun endTransaction(successful: Boolean): QueryResult<Unit> {
            if (enclosing == null) {
                sqlJsRun(db, if (successful) "COMMIT" else "ROLLBACK")
            } else if (!successful) {
                sqlJsRun(db, "ROLLBACK TO SAVEPOINT SP_$depth")
            }
            transaction = enclosing
            return QueryResult.Value(Unit)
        }

        override val enclosingTransaction: Transacter.Transaction? = enclosing
    }
}

/** Collects bound values by 0-based index into [bound] (sql.js's own array-bind form, positional
 * by order - matches sqldelight's own 0-indexed [SqlPreparedStatement] calls 1:1). `Long` ->
 * `Double`: JS has no 64-bit integer type; sql.js itself only ever stores/returns plain
 * `number`s, same precision ceiling every value here already lives under once it crosses this
 * boundary. */
private class BoundStatement(private val bound: Array<Any?>) : SqlPreparedStatement {
    override fun bindBytes(index: Int, bytes: ByteArray?) {
        bound[index] = bytes?.let { toInt8Array(it) }
    }

    override fun bindLong(index: Int, long: Long?) {
        bound[index] = long?.toDouble()
    }

    override fun bindDouble(index: Int, double: Double?) {
        bound[index] = double
    }

    override fun bindString(index: Int, string: String?) {
        bound[index] = string
    }

    override fun bindBoolean(index: Int, boolean: Boolean?) {
        bound[index] = boolean?.let { if (it) 1 else 0 }
    }
}

private class SqlJsCursor(private val stmt: dynamic) : SqlCursor {
    private var row: Array<Any?> = emptyArray()

    override fun next(): QueryResult<Boolean> {
        val hasRow = sqlJsStep(stmt)
        row = if (hasRow) sqlJsGetRow(stmt) else emptyArray()
        return QueryResult.Value(hasRow)
    }

    override fun getString(index: Int): String? = row.getOrNull(index) as? String

    override fun getLong(index: Int): Long? = (row.getOrNull(index) as? Double)?.toLong()

    override fun getBytes(index: Int): ByteArray? = (row.getOrNull(index))?.let { fromInt8Array(it) }

    override fun getDouble(index: Int): Double? = row.getOrNull(index) as? Double

    override fun getBoolean(index: Int): Boolean? = (row.getOrNull(index) as? Double)?.let { it != 0.0 }
}

private fun toInt8Array(bytes: ByteArray): dynamic {
    val arr = js("new Uint8Array(bytes.length)")
    for (i in bytes.indices) arr[i] = bytes[i].toInt() and 0xFF
    return arr
}

private fun fromInt8Array(value: Any): ByteArray {
    val length: Int = js("value.length")
    return ByteArray(length) { i -> (js("value[i]") as Int).toByte() }
}
