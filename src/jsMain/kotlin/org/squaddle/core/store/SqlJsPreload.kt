package org.squaddle.core.store

import kotlinx.coroutines.await

/** The resolved sql.js module, once [preloadSqlJsDriver] has completed. `null` beforehand. */
internal var sqlJsStatic: dynamic = null
    private set

/**
 * Loads sql.js's WASM module - genuinely async (fetch + WASM compile), unlike every other
 * platform's SQLite, which is why this is a separate step rather than part of [createSqlDriver]
 * itself ([createSqlDriver]'s `expect fun` signature is synchronous on every platform, matching
 * jvm/android where that's true). Must be awaited once, before the first [createSqlDriver] call
 * on this target. [locateWasm] resolves the on-disk/served path of the `.wasm` binary - left to
 * the caller (webclient) since that's bundler-specific (see `vite-shims/`), not something `core`
 * should need to know about.
 */
public suspend fun preloadSqlJsDriver(locateWasm: (fileName: String) -> String) {
    val config = js("({})")
    config.locateFile = locateWasm
    sqlJsStatic = initSqlJs(config).await()
}
