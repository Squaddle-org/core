package org.squaddle.core.store

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SqlJsPreloadTest {
    @Test
    fun preloadLoadsWasmAndOpensADatabase() = runTest {
        preloadSqlJsDriver { fileName -> "/node_modules/sql.js/dist/$fileName" }

        val db = sqlJsNewDatabase(sqlJsStatic)
        sqlJsRun(db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
        sqlJsRun(db, "INSERT INTO t (id, name) VALUES (1, 'hello')")

        val stmt = sqlJsPrepare(db, "SELECT id, name FROM t WHERE id = ?")
        assertTrue(sqlJsBind(stmt, arrayOf(1)))
        assertTrue(sqlJsStep(stmt))
        val row = sqlJsGetRow(stmt)
        assertEquals(1.0, row[0])
        assertEquals("hello", row[1])
        sqlJsFree(stmt)
        sqlJsClose(db)
    }
}
