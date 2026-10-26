package org.squaddle.core.store

import app.cash.sqldelight.db.SqlDriver

/** ADR-0009: a real browser driver exists (`app.cash.sqldelight:web-worker-driver-js`/
 * `-wasm-js`, SQLDelight 2.4.1+) but needs a Web Worker + SQL.js wired up - real integration
 * work, deliberately deferred past this target's initial landing (tracked in ADR-0009's
 * Consequences). `webclient`'s local-storage layer must solve this before it can call
 * [LocalStore] for real; nothing in `commonMain` calls [createSqlDriver] at module-init time, so
 * this stub is safe to land without blocking anything else on this target. */
public actual fun createSqlDriver(name: String): SqlDriver =
    throw UnsupportedOperationException(
        "SqlDriverJs is unimplemented - see ADR-0009 (needs a Web Worker + SQL.js driver, app.cash.sqldelight:web-worker-driver-js)",
    )
