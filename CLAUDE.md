# CLAUDE.md — core repo

Kotlin Multiplatform implementation of the Squaddle protocol. The spec lives in a separate repo,
expected as sibling checkout `../spec`. **Read `../spec/protocol/PROTOCOL.md`, `../spec/ARCHITECTURE.md`
and `../spec/ROADMAP.md` before coding.** The spec wins over this code. If the spec is missing or
ambiguous, propose a spec change (PR in `../spec`) instead of inventing behavior here.

## Hard rules
- `crypto/` is the only package touching libsodium. Only constructions from PROTOCOL.md §1. Nonces random 24 bytes.
- Everything hashed or signed goes through `encoding/CanonicalCbor`. Never sign JSON.
- Every signed/encrypted structure: round-trip test + reject tests + test vectors.
  Generate vectors with `./gradlew generateTestVectors -PspecDir=../spec`, then open a PR in `spec`.
- After a spec release: bump `SPEC_VERSION`, run `./gradlew allTests`.
- Membership rules must stay identical to `../relay/internal/membership` — both pass the same vectors.
- No platform-specific code in `commonMain` except via expect/actual. No `!!` outside tests. Explicit API mode.
- Never log keys, seeds, invite secrets or URL fragments.

## Commands
```bash
SQUADDLE_SPEC_DIR=../spec ./gradlew jvmTest
./gradlew allTests
./gradlew publishToMavenLocal
```

## Versions
`gradle/libs.versions.toml` is a starting point — bump to current stable on first build and verify the
libsodium bindings support each target before enabling it.
