package org.lumina

import io.ktor.server.application.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import org.lumina.routes.approvalRoute
import org.lumina.routes.groupManagerRoute
import org.lumina.routes.groupRoute
import org.lumina.routes.weixinAuthRoute

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

