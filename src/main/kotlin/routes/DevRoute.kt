package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT

/**
 * 调试环境路由，生产环境下不集成
 *
 * 功能：
 * - 获取当前登录用户的 weixinOpenId
 */
fun Routing.devRoute(appId: String, appSecret: String) {
    route("/dev") {
        authenticate {
            get("/weixinOpenId") {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                call.respond(weixinOpenId)
            }
        }
    }
}
