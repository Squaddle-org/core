rootProject.name = "core"

pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}

plugins {
    // Auto-provisions the JDK 17 build toolchain (kotlin { jvmToolchain(17) }) so contributors
    // and CI don't need a matching JDK pre-installed.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

// JVM-only manual/integration-test harness (ROADMAP.md M3) - not published, depends on this
// root project's jvm target via project(":").
include(":cli")
