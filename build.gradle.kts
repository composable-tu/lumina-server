/**
 * Copyright (c) 2025 LuminaPJ
 * SM2 Key Generator is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

val ktor_version = "3.3.0"
val exposed_version = "1.0.0-rc-1"
val h2_version = "2.4.240"
val kotlin_version = "2.2.20"
val logback_version = "1.5.18"
val postgres_version = "42.7.8"
val kona_sm_version = "1.0.18"
val tika_version = "3.2.3"
val apache_poi_version = "5.4.1"

plugins {
    kotlin("jvm") version "2.2.20"
    id("io.ktor.plugin") version "3.3.0"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.2.20"
    id("com.github.ben-manes.versions") version "0.53.0"
}

val luminaVersion = "0.0.1"

group = "org.lumina"
version = luminaVersion

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
    // Ktor 3.3.0 存在某些情况下生成 OpenAPI 时会发生无限递归的问题
    // https://youtrack.jetbrains.com/issue/KTOR-8878/OpenApi-generation-StackOverflowError
    /*
    @OptIn(OpenApiPreview::class) openApi {
        target = project.layout.projectDirectory.file("api.json")
        title = "Lumina API"
        summary = "Lumina API"
        description = "Lumina API"
        version = luminaVersion
    }
    */
    fatJar {
        archiveFileName = "lumina-server-all.jar"
    }
}

// 在编译时自动生成 OpenAPI
/*
tasks.processResources {
    dependsOn("buildOpenApi")
}
*/

dependencies {
    implementation("com.tencent.kona:kona-crypto:$kona_sm_version")
    implementation("com.tencent.kona:kona-provider:$kona_sm_version")
    implementation("io.ktor:ktor-client-core:$ktor_version")
    implementation("io.ktor:ktor-client-cio:$ktor_version")
    implementation("io.ktor:ktor-client-cio-jvm:$ktor_version")
    implementation("io.ktor:ktor-client-content-negotiation:$ktor_version")
    implementation("io.ktor:ktor-server-core:$ktor_version")
    implementation("io.ktor:ktor-server-openapi:$ktor_version")
    implementation("io.ktor:ktor-server-auth:$ktor_version")
    implementation("io.ktor:ktor-server-auth-jwt:$ktor_version")
    implementation("io.ktor:ktor-server-content-negotiation:$ktor_version")
    implementation("io.ktor:ktor-serialization-kotlinx-json")
    implementation("org.jetbrains.exposed:exposed-core:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-jdbc:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-dao:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-java-time:$exposed_version")
    implementation("org.jetbrains.exposed:exposed-migration:1.0.0-beta-5")
    implementation("com.h2database:h2:$h2_version")
    implementation("org.postgresql:postgresql:$postgres_version")
    implementation("io.ktor:ktor-server-netty:$ktor_version")
    implementation("ch.qos.logback:logback-classic:$logback_version")
    implementation("io.ktor:ktor-server-config-yaml:$ktor_version")
    implementation("io.ktor:ktor-server-host-common:$ktor_version")
    implementation("io.ktor:ktor-server-status-pages:$ktor_version")
    testImplementation("io.ktor:ktor-server-test-host:$ktor_version")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlin_version")
    implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.7.1-0.6.x-compat")
    implementation("ch.qos.logback:logback-classic:1.5.18")
    implementation("org.apache.tika:tika-core:$tika_version")
    implementation("org.apache.tika:tika-parsers:$tika_version")
    implementation("org.apache.poi:poi-ooxml:$apache_poi_version")
    implementation("commons-io:commons-io:2.20.0")
}

