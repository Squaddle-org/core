import RealModule from "../build/js/node_modules/libsodium-sumo/dist/modules-sumo-esm/libsodium-sumo.mjs";

// No top-level await: a bare CJS require('libsodium-sumo') elsewhere in the dependency graph
// (libsodium-wrappers-sumo's own internals) cannot consume an async ES module. RealModule's
// _-prefixed properties are populated asynchronously after WASM instantiation, but RealModule
// itself (the object reference) is available synchronously at import time - these forwarding
// functions just read the property at CALL time, by which point the Kotlin bridge's own
// initialization flow (which awaits `ready` before calling anything) has already guaranteed the
// WASM module is live.
export const ready = RealModule.ready;
export function crypto_generichash(...args) { return RealModule._crypto_generichash(...args); }
export function crypto_hash_sha256(...args) { return RealModule._crypto_hash_sha256(...args); }
export function crypto_hash_sha512(...args) { return RealModule._crypto_hash_sha512(...args); }
export function crypto_hash_sha256_init(...args) { return RealModule._crypto_hash_sha256_init(...args); }
export function _sodium_init(...args) { return RealModule._sodium_init(...args); }
export default RealModule;
