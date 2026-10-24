# Squaddle Core

Kotlin Multiplatform library implementing the [Squaddle protocol](https://github.com/squaddle-org/spec):
identity, crypto facade (libsodium), membership log, encrypted op-log, LWW state, sync client, backup.

Artifact: `org.squaddle:core` · Targets: JVM, Android (later JS/Wasm, iOS)

```bash
gradle wrapper --gradle-version <current-stable>   # once
./gradlew jvmTest                                   # uses spec release from SPEC_VERSION
SQUADDLE_SPEC_DIR=../spec ./gradlew jvmTest         # against a local spec checkout
./gradlew publishToMavenLocal                       # for the android composite build
```
