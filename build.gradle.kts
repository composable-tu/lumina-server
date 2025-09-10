val exposed_version = "1.0.0-beta-5"
val h2_version = "2.3.232"
val kotlin_version = "2.2.20"
val logback_version = "1.5.18"
val postgres_version = "42.7.7"
val kona_sm_version = "1.0.18"
val tika_version = "3.2.2"
val apache_poi_version = "5.4.1"

plugins {
    kotlin("jvm") version "2.2.20"
    id("io.ktor.plugin") version "3.2.3"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.2.20"
    id("com.github.ben-manes.versions") version "0.52.0"
}

group = "org.lumina"
version = "0.0.1"

application {
    mainClass = "io.ktor.server.netty.EngineMain"

    val isDevelopment: Boolean = project.ext.has("development")
    applicationDefaultJvmArgs = listOf("-Dio.ktor.development=$isDevelopment")
}

repositories {
    mavenCentral()
    google()
}

ktor {
    fatJar {
        archiveFileName = "lumina-server-all.jar"
    }
}

dependencies {
    implementation("com.tencent.kona:kona-crypto:$kona_sm_version")
    implementation("com.tencent.kona:kona-provider:$kona_sm_version")
    implementation("io.ktor:ktor-client-core")
    implementation("io.ktor:ktor-client-cio")
    implementation("io.ktor:ktor-server-core")
    implementation("io.ktor:ktor-server-auth")
    implementation("io.ktor:ktor-server-auth-jwt")
    implementation("io.ktor:ktor-server-content-negotiation")
    implementation("io.ktor:ktor-client-content-negotiation")
    implementation("io.ktor:ktor-serialization-kotlinx-json")
    implementation("org.jetbrains.exposed:exposed-core:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-jdbc:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-dao:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-java-time:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-migration:$exposed_version")
    implementation("com.h2database:h2:$h2_version")
    implementation("org.postgresql:postgresql:$postgres_version")
    implementation("io.ktor:ktor-server-netty")
    implementation("ch.qos.logback:logback-classic:$logback_version")
    implementation("io.ktor:ktor-server-config-yaml")
    implementation("io.ktor:ktor-server-host-common")
    implementation("io.ktor:ktor-server-status-pages")
    implementation("io.ktor:ktor-client-cio-jvm:3.2.3")
    testImplementation("io.ktor:ktor-server-test-host")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlin_version")
    implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.7.1-0.6.x-compat")
    implementation("ch.qos.logback:logback-classic:1.5.18")
    implementation("org.apache.tika:tika-core:$tika_version")
    implementation("org.apache.tika:tika-parsers:$tika_version")
    implementation("org.apache.poi:poi-ooxml:$apache_poi_version")
}

