plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.kotlin.multiplatform.library)
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
        compileSdk = 36
        minSdk = 26
        withHostTestBuilder {}.configure {}
    }
    // M5: js(IR) { browser() } / wasmJs { browser() } — only after verifying libsodium bindings support it
    // M6: iosArm64(); iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation(libs.coroutines.core)
            implementation(libs.serialization.json)
            implementation(libs.libsodium)
            implementation(libs.ktor.client.core)
            implementation(libs.ktor.client.websockets)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.coroutines.test)
        }
        jvmTest.dependencies {
            implementation(libs.kotest.property)
        }
        getByName("androidHostTest").dependencies {
            implementation(kotlin("test"))
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

// TODO(M0): register `generateTestVectors` (JVM main/test source set) writing into -PspecDir=../spec/protocol/testvectors

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
    }
}
