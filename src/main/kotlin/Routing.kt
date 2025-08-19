package org.lumina

import io.ktor.server.application.*
import io.ktor.server.routing.*
import org.lumina.routes.*
import org.lumina.routes.subroutes.weixinSoterRoute

fun Application.configureRouting(appId: String, appSecret: String) {
    val environment = environment.config.property("ktor.environment").getString()
    routing {
        weixinAuthRoute(appId, appSecret)
        groupRoute(appId, appSecret)
        groupManagerRoute(appId, appSecret)
        approvalRoute(appId, appSecret)
        weixinSoterRoute(appId, appSecret)
        userRoute(appId, appSecret)
        taskRoute(appId, appSecret)
        if (environment.isDev()) devRoute(appId, appSecret)
    }
}

private fun String.isDev(): Boolean {
    return this == "development" || this == "dev" || this == "test"
}
