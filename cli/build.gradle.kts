// JVM CLI harness (ROADMAP.md M3) - manual smoke-test tool + the end-to-end integration test's
// driver. Not published (no maven-publish, no group/version beyond Gradle's own defaults).
plugins {
    // No version here: the Kotlin Gradle plugin is already resolved (and version-pinned) by the
    // root project's kotlin-multiplatform application - specifying a second version for what
    // Gradle treats as the same underlying plugin artifact triggers a classpath conflict.
    id("org.jetbrains.kotlin.jvm")
    application
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":")) // the root KMP module's jvm target - org.squaddle:core
    implementation(libs.coroutines.core)
}

application {
    mainClass.set("org.squaddle.cli.MainKt")
}
