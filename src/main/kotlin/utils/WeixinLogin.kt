package org.linlangwen.utils

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.Transaction
import org.linlangwen.models.Users

@Serializable
data class WeixinLoginResponse(
    val openid: String? = null,
    val session_key: String? = null,
    val unionid: String? = null,
    val errcode: Int? = null,
    val errmsg: String? = null
)

private val client = HttpClient(CIO)
private val json = Json { ignoreUnknownKeys = true }

suspend fun code2Session(appId: String, appSecret: String, code: String): WeixinLoginResponse {
    val response = client.get {
        url {
            protocol = URLProtocol.HTTPS
            host = "api.weixin.qq.com"
            path("sns", "jscode2session")
            parameters.apply {
                append("appid", appId)
                append("secret", appSecret)
                append("js_code", code)
                append("grant_type", "authorization_code")
            }
        }
    }
    return json.decodeFromString<WeixinLoginResponse>(response.bodyAsText())
}

suspend fun code2WeixinOpenIdOrNull(appId: String, appSecret: String, code: String): String? {
    return code2Session(appId, appSecret, code).openid
}

suspend fun code2WeixinUnionIdOrNull(appId: String, appSecret: String, code: String): String? {
    return code2Session(appId, appSecret, code).unionid
}


fun Transaction.getUserIdByWeixinOpenIdOrNullFromDB(openId: String): String? {
    val user = Users.select(Users.weixinOpenId eq openId).firstOrNull()
    return user?.get(Users.userId)
}
