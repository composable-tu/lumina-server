package org.linlangwen

import io.ktor.server.application.*
import io.ktor.server.netty.EngineMain
import io.ktor.server.routing.*
import org.linlangwen.routes.approvalRoute
import org.linlangwen.routes.groupManagerRoute
import org.linlangwen.routes.groupRoute
import org.linlangwen.routes.weixinAuthRoute

fun main(args: Array<String>) {
   EngineMain.main(args)
}

fun Application.module() {
    val appId = environment.config.property("appId").getString()
    val appSecret = environment.config.property("appSecret").getString()
    configureSecurity()
    configureSerialization()
    configureDatabases()
    configureRouting()
    routing{
        weixinAuthRoute(appId, appSecret)
        groupRoute(appId, appSecret)
        groupManagerRoute(appId, appSecret)
        approvalRoute()
    }
}

