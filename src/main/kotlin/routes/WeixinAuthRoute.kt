package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.OAuth1aException.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.jdbc.update
import org.lumina.generateJWE
import org.lumina.models.Users
import org.lumina.utils.code2WeixinOpenIdOrNull
import org.lumina.utils.normalized

/**
 * 微信认证路由
 *
 * 功能：
 * - 在微信小程序端未保存 JWT 的情况下，POST `/weixin/login` 得到服务端加密的 Weixin Open ID JWT
 * - 微信侧 GET `/weixin/validate` 验证 JWT 是否仍然有效
 */
fun Routing.weixinAuthRoute(appId: String, appSecret: String) {
    route("/weixin") {
        post("/login") {
            val request = call.receive<WeixinLoginRequest>().normalized() as WeixinLoginRequest
            val weixinUserInfo = code2WeixinOpenIdOrNull(appId, appSecret, request.code)
            val weixinOpenId = weixinUserInfo.openid ?: throw MissingTokenException()
            val weixinUnionId = weixinUserInfo.unionid
            val jwt = generateJWE(weixinOpenId, weixinUnionId)
            if (weixinUnionId != null) transaction {
                val userRow = Users.selectAll().where { Users.weixinOpenId eq weixinOpenId }.firstOrNull()
                if (userRow != null) Users.update({ Users.weixinOpenId eq weixinOpenId }) {
                    it[this.weixinUnionId] = weixinUnionId
                }
            }
            call.respond(WeixinLoginResponse(jwt))
        }
        authenticate {
            get("/validate") {
                call.respond(HttpStatusCode.OK)
            }
        }
    }
}

@Serializable
private data class WeixinLoginRequest(val code: String)

@Serializable
private data class WeixinLoginResponse(val jwt: String)