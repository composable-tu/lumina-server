package org.lumina

import io.ktor.server.application.*
import io.ktor.server.netty.*

fun main(args: Array<String>) {
    EngineMain.main(args)
}

fun Application.module() {
    val appId = environment.config.property("wx.appId").getString()
    val appSecret = environment.config.property("wx.appSecret").getString()
    configureSecurity()
    configureSerialization()
    configureDatabases()
    configureRouting(appId, appSecret)
}

