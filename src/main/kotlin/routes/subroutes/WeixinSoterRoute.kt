package org.lumina.routes.subroutes

import io.ktor.server.auth.*
import io.ktor.server.routing.*

fun Routing.weixinSoterRoute(appId: String, appSecret: String) {
    route("/soter") {
        authenticate {
            get("/check") {

            }
        }
    }
}