package org.linlangwen.routes

import io.ktor.server.auth.*
import io.ktor.server.auth.OAuth1aException.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.transactions.transaction
import org.linlangwen.generateJWT
import org.linlangwen.models.UserGroups
import org.linlangwen.models.Users
import org.linlangwen.utils.code2WeixinOpenIdOrNull
import org.linlangwen.utils.normalized

/**
 * 微信认证路由
 *
 * 功能：
 * - 在微信小程序端未保存 JWT 的情况下，POST `/weixin/login` 得到服务端加密的 Weixin Open ID JWT
 */
fun Routing.weixinAuthRoute(appId: String, appSecret: String) {
    route("/weixin") {
        post("/login") {
            val request = call.receive<WeixinLoginRequest>().normalized() as WeixinLoginRequest
            val weixinOpenId = code2WeixinOpenIdOrNull(appId, appSecret,request.code)
            if (weixinOpenId == null) throw MissingTokenException()
            val jwt = generateJWT(weixinOpenId)
            call.respond(WeixinLoginResponse(jwt))
        }
        authenticate {

        }
    }
}
@Serializable
data class WeixinLoginRequest(val code: String)

@Serializable
data class WeixinLoginResponse(val jwt: String)