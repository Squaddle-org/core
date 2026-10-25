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
        compileSdk = 36
        minSdk = 26
        withHostTestBuilder {}.configure {}
        // Real on-device run of the native libsodium bindings (M0 only verified JVM + that this
        // target compiles) - no emulator/device in this sandbox, so only compilation is verified
        // here; run `./gradlew connectedAndroidTest` on real hardware.
        withDeviceTestBuilder { sourceSetTreeName = "test" }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
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
    }
}
