// ADR-0009 crypto-bridge fix: multiplatform-crypto-libsodium-bindings' generated bridge
// statically ESM-imports named exports (crypto_generichash, _sodium_init, ready, ...) from a
// package literally named 'libsodium-sumo', but that package's real ESM build only has
// `export default Module` (an Emscripten module object whose raw _-prefixed C exports are
// attached asynchronously, after Module.ready resolves) - no static named exports exist at all.
// This aliases the literal import specifier 'libsodium-sumo' to a hand-written shim (below) that
// re-exports exactly the symbols the bridge needs, lazily forwarding to the now-populated Module
// object at call time.
//
// __dirname here is NOT this webpack.config.d/ directory - Kotlin's config.d merge mechanism
// inlines this file's body into the generated karma.conf.js/webpack config under
// build/js/packages/<module>/, at a depth that can differ per task (jsBrowserTest vs a
// production bundle task). Walk up from there until webpack.config.d/ itself is found, rather
// than assuming a fixed relative depth or relying on process.cwd() (observed unreliable across
// different Gradle-spawned Node subprocesses).
const path = require("path");
const fs = require("fs");
function findProjectRoot(startDir) {
  let dir = startDir;
  for (let i = 0; i < 10; i++) {
    if (fs.existsSync(path.join(dir, "webpack.config.d"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("libsodium-sumo-shim.js: could not locate project root (webpack.config.d/) walking up from " + startDir);
}
const projectRoot = findProjectRoot(__dirname);
config.resolve = config.resolve || {};
config.resolve.alias = Object.assign({}, config.resolve.alias, {
  "libsodium-sumo$": path.resolve(projectRoot, "webpack.config.d/libsodium-sumo-real-shim.mjs"),
});

// libsodium-sumo.mjs's own Node-compat __dirname/__filename polyfill dynamically imports 'url'
// and 'path', guarded by a runtime typeof-process check that's always false in a browser - dead
// code there, but webpack's static import analysis doesn't see through the guard.
config.resolve.fallback = Object.assign({}, config.resolve.fallback, {
  url: false,
  path: false,
});
