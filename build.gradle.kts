plugins {
    kotlin("jvm") version "2.1.20"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("org.jetbrains.kotlin.plugin.serialization") version "1.8.10"
}

group = "com.danaepp"
version = "2.3-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17)
}

// Lock dependency version
val montoyaVersion = "2023.12.1"
val kotlinxSerializationVersion = "1.6.3"
val kotlinxCoroutinesVersion = "1.9.0"
val junitVersion = "5.10.2"
val mockkVersion = "1.14.5"

dependencies {
    //implementation(kotlin("stdlib"))      // no explicit version
    implementation("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinxSerializationVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinxCoroutinesVersion")

    // JUnit 5 (Jupiter) API and engine
    testImplementation(kotlin("test"))    // no explicit version
    testImplementation("io.mockk:mockk:$mockkVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

tasks.test {
    useJUnitPlatform()
}