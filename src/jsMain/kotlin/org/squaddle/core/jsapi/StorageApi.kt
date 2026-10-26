@file:OptIn(ExperimentalJsExport::class)

package org.squaddle.core.jsapi

/** `@JsExport` entry point for `org.squaddle.core.store.preloadSqlJsDriver` (that package itself
 * isn't exported - everything JS-facing goes through this package, same as every other facade
 * here). Must be awaited once, before the first [SessionApi.open] call. */
@JsExport
public object StorageApi {
    public suspend fun preloadSqlJsDriver(locateWasm: (fileName: String) -> String) {
        org.squaddle.core.store.preloadSqlJsDriver(locateWasm)
    }
}
