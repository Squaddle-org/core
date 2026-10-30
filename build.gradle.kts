import org.gradle.api.publish.maven.MavenPublication

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.sqldelight)
    `maven-publish`
}

group = "org.squaddle"
version = providers.gradleProperty("squaddle.version").getOrElse("0.1.0-SNAPSHOT")

kotlin {
    explicitApi()
    jvmToolchain(17)

    jvm()
    // AGP 9: KMP android target is configured via this android{} block (inside kotlin{}), not a
    // separate androidTarget() + top-level android{} — see com.android.kotlin.multiplatform.library.
    android {
        namespace = "org.squaddle.core"
        // Bumped from 36 (android app module's M4b item 12: a release build failed its own
        // AAR-metadata check otherwise - `io.ktor:ktor-client-okhttp`'s `okhttp-android:5.5.0`
        // transitive dependency requires compiling against API 37+, and that check runs on
        // every consumer of this module, not just this module's own build).
        compileSdk = 37
        minSdk = 26
        withHostTestBuilder {}.configure {}
        // Real on-device run of the native libsodium bindings (M0 only verified JVM + that this
        // target compiles) - no emulator/device in this sandbox, so only compilation is verified
        // here; run `./gradlew connectedAndroidTest` on real hardware.
        withDeviceTestBuilder { sourceSetTreeName = "test" }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }
    // M5/ADR-0009: js(IR), not wasmJs - no official wasmJs variant exists for the pinned crypto
    // library (confirmed: ADR-0009). The crypto bridge's own broken npm import also needed a
    // fix - see webpack.config.d/ and ADR-0009's "crypto bridge" note. Runtime correctness
    // against a real browser is still unverified (ADR-0009's one open item).
    js {
        browser {
            testTask {
                useKarma {
                    useChromiumHeadless()
                }
            }
        }
        binaries.library()
        useEsModules()
        generateTypeScriptDefinitions()
    }
    // M6: iosArm64(); iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation(libs.coroutines.core)
            implementation(libs.serialization.json)
            implementation(libs.libsodium)
            implementation(libs.ktor.client.core)
            implementation(libs.ktor.client.websockets)
            implementation(libs.sqldelight.runtime)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.coroutines.test)
        }
        jvmMain.dependencies {
            implementation(libs.sqldelight.driver.sqlite)
            implementation(libs.ktor.client.okhttp)
        }
        jvmTest.dependencies {
            implementation(libs.kotest.property)
            implementation(libs.ktor.client.mock)
        }
        getByName("androidMain").dependencies {
            implementation(libs.sqldelight.driver.android)
            implementation(libs.ktor.client.okhttp)
        }
        getByName("androidHostTest").dependencies {
            implementation(kotlin("test"))
        }
        getByName("androidDeviceTest").dependencies {
            implementation(kotlin("test"))
            implementation(libs.coroutines.test)
            implementation(libs.androidx.test.runner)
            implementation(libs.androidx.test.ext.junit)
        }
        getByName("jsMain").dependencies {
            implementation(libs.ktor.client.js)
            // No official SqlDelight sync browser driver exists (ADR-0009) - SqlJsDriver.kt
            // hand-wraps this directly, synchronously, matching jvm/android's generated
            // (non-async) SquaddleDb query API.
            implementation(npm("sql.js", "1.15.2"))
        }
        getByName("jsTest").dependencies {
            implementation(kotlin("test"))
            implementation(libs.coroutines.test)
        }
    }
}

sqldelight {
    databases {
        create("SquaddleDb") {
            packageName.set("org.squaddle.core.store")
        }
    }
}

// Test vectors from the spec: SQUADDLE_SPEC_DIR (local checkout) wins, else the release pinned in SPEC_VERSION.
val specVectorsDir = layout.buildDirectory.dir("spec/testvectors")
tasks.register<Exec>("fetchSpec") {
    description = "Fetch test vectors for the spec version in SPEC_VERSION (or copy from SQUADDLE_SPEC_DIR)"
    commandLine("./scripts/fetch-spec.sh", specVectorsDir.get().asFile.absolutePath)
}
tasks.withType<Test>().configureEach {
    dependsOn("fetchSpec")
    systemProperty("squaddle.testvectors", specVectorsDir.get().asFile.absolutePath)
}

tasks.register<JavaExec>("generateTestVectors") {
    group = "verification"
    description = "Regenerates protocol/testvectors/{identity,devicecert}.json into -PspecDir (default ../spec). Never hand-edit the output."
    val jvmMain = kotlin.targets.getByName("jvm").compilations.getByName("main")
    dependsOn(jvmMain.compileTaskProvider)
    classpath = files(jvmMain.output.allOutputs, jvmMain.runtimeDependencyFiles)
    mainClass.set("org.squaddle.core.testvectors.GenerateTestVectorsKt")
    args(providers.gradleProperty("specDir").getOrElse("../spec"))
}

publishing {
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/squaddle-org/core")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
        // The real no-token target (android's own release verification step resolves
        // org.squaddle:core from here with nothing but a plain repository URL - GitHub Packages'
        // Maven registry, above, requires a token to resolve even public packages, which was the
        // whole reason this exists rather than just using that one). Plain `maven-publish` to a
        // local build/ directory; release.yml's own publish step pushes that directory's content
        // to this repo's `gh-pages` branch (plain git, no extra action/service) - GitHub Pages
        // then serves it as a standard static Maven repository layout, fully anonymous. Requires
        // GitHub Pages enabled for this repo (Settings -> Pages -> Deploy from branch ->
        // gh-pages) - a one-time manual step, not something this build or workflow can flip on
        // itself.
        maven {
            name = "GitHubPages"
            url = uri(layout.buildDirectory.dir("maven-repo"))
        }
    }
    // Real POM metadata instead of Gradle's own auto-generated bare-minimum one - applies to
    // every KMP target's publication (jvm/android/js/kotlinMultiplatform) at once.
    publications.withType<MavenPublication>().configureEach {
        pom {
            name.set("Squaddle Core")
            description.set("Kotlin Multiplatform implementation of the Squaddle protocol - crypto, sync client, and local store, shared across the Android app, CLI, and web client.")
            inceptionYear.set("2026")
            url.set("https://github.com/squaddle-org/core")
            licenses {
                license {
                    name.set("Apache-2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    distribution.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }
            developers {
                developer {
                    id.set("squaddle-org")
                    name.set("The Squaddle Authors")
                    url.set("https://github.com/squaddle-org")
                }
            }
            scm {
                url.set("https://github.com/squaddle-org/core")
                connection.set("scm:git:git://github.com/squaddle-org/core.git")
                developerConnection.set("scm:git:ssh://git@github.com/squaddle-org/core.git")
            }
        }
    }
}
