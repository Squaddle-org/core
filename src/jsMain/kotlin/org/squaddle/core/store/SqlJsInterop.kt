@file:Suppress("unused")

package org.squaddle.core.store

import kotlin.js.Promise

/**
 * Minimal Kotlin/JS external bindings for sql.js (ADR-0009: no official SqlDelight sync browser
 * driver exists, so [SqlJsDriver] wraps this directly). `dynamic` throughout rather than typed
 * `external class`/`external interface` declarations - sql.js's `SqlJsStatic.Database` is an ES
 * class *value* handed back inside an async-resolved object, not a top-level module export;
 * modeling that as a constructible typed external binding is the awkward part of this interop
 * surface, so it's kept untyped here and wrapped immediately by [SqlJsDriver]'s typed Kotlin API.
 */
@JsModule("sql.js")
internal external fun initSqlJs(config: dynamic = definedExternally): Promise<dynamic>

internal fun sqlJsNewDatabase(sqlJsStatic: dynamic): dynamic = js("new sqlJsStatic.Database()")
internal fun sqlJsRun(db: dynamic, sql: String) { js("db.run(sql)") }
internal fun sqlJsPrepare(db: dynamic, sql: String): dynamic = js("db.prepare(sql)")
internal fun sqlJsBind(stmt: dynamic, params: Array<Any?>): Boolean = js("stmt.bind(params)")
internal fun sqlJsStep(stmt: dynamic): Boolean = js("stmt.step()")
internal fun sqlJsGetRow(stmt: dynamic): Array<Any?> = js("stmt.get()")
internal fun sqlJsFree(stmt: dynamic): Boolean = js("stmt.free()")
internal fun sqlJsGetRowsModified(db: dynamic): Int = js("db.getRowsModified()")
internal fun sqlJsClose(db: dynamic) { js("db.close()") }
