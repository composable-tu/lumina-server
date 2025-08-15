package org.lumina.utils.security

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.lumina.fields.GeneralFields.WEIXIN_MP_SERVER_OPEN_API_HOST
import org.lumina.utils.commonClient
import org.lumina.utils.getWeixinAccessTokenOrNull

suspend fun weixinSoterCheck(appId: String, appSecret: String, request: WeixinSoterCheckRequest): Boolean {
    val accessToken =
        getWeixinAccessTokenOrNull(appId, appSecret) ?: throw IllegalStateException("获取微信接口调用凭证失败")
    val response = commonClient.post {
        url {
            protocol = URLProtocol.HTTPS
            host = WEIXIN_MP_SERVER_OPEN_API_HOST
            path("cgi-bin", "soter", "verify_signature")
            parameters.append("access_token", accessToken)
        }
        contentType(ContentType.Application.Json)
        setBody(request)
    }
    val result = json.decodeFromString<WeixinSoterCheckResponse>(response.bodyAsText())
    return result.is_ok == true
}

/**
 * 微信 Soter 生物认证请求体
 *
 * @property openid 微信 Open ID
 * @property json_string 签名字符串，从微信小程序端调用 `wx.startSoterAuthentication` 获取
 * @property json_signature 签名，从微信小程序端调用 `wx.startSoterAuthentication` 获取
 */
@Serializable
data class WeixinSoterCheckRequest(
    val openid: String, val json_string: String, val json_signature: String
)

/**
 * 微信 Soter 生物认证响应体
 *
 * @property errcode 错误码
 * @property errmsg 错误信息
 * @property is_ok 是否通过认证
 */
@Serializable
data class WeixinSoterCheckResponse(
    val errcode: Int? = null, val errmsg: String? = null, val is_ok: Boolean? = null
)

@Serializable
data class SoterResultFromUser(val json_string: String, val json_signature: String)

private val json = Json { ignoreUnknownKeys = true }
