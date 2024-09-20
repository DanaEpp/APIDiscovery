plugins {
    kotlin("jvm") version "1.9.23"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("org.jetbrains.kotlin.plugin.serialization") version "1.8.10"
}

group = "com.danaepp"
version = "2.0-SNAPSHOT"

repositories {
    mavenCentral()
}

// Lock dependency version
val montoyaVersion = "2023.12.1"
val kotlinxSerializationVersion = "1.6.3"
val kotlinxCoroutinesVersion = "1.9.0"

dependencies {
    implementation("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$kotlinxSerializationVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinxCoroutinesVersion")
}

tasks.test {
    useJUnitPlatform()
}