package org.lumina

import io.ktor.server.application.*
import io.ktor.server.routing.*
import org.lumina.routes.approvalRoute
import org.lumina.routes.groupManagerRoute
import org.lumina.routes.groupRoute
import org.lumina.routes.weixinAuthRoute

fun Application.configureRouting(appId: String, appSecret: String) {
    routing {
        weixinAuthRoute(appId, appSecret)
        groupRoute(appId, appSecret)
        groupManagerRoute(appId, appSecret)
        approvalRoute()
    }
}
