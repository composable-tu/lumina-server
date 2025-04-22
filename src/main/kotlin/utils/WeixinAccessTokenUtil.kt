package org.linlangwen.utils

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Serializable

/**
 * 微信接口调用凭据响应体
 *
 * @param access_token 获取到的凭证
 * @param expires_in 凭证有效时间，单位：秒。目前是7200秒之内的值。
 * @param errcode 错误码
 * @param errmsg 错误信息
 * @see [微信开放文档](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/mp-access-token/getAccessToken.html)
 */
@Serializable
data class WeixinAccessTokenResponse(
    val access_token: String? = null, val expires_in: Int? = null, val errcode: Int? = null, val errmsg: String? = null
)

private val client = HttpClient(CIO)

/**
 * 获取接口调用凭据
 *
 * @param appId 小程序 appId
 * @param appSecret 小程序 appSecret
 * @return 接口调用凭据或 null
 * @see [微信开放文档](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/mp-access-token/getAccessToken.html)
 */
suspend fun getWeixinAccessTokenOrNull(appId: String, appSecret: String): String? {
    val response = client.get {
        url {
            protocol = URLProtocol.HTTPS
            host = "api.weixin.qq.com"
            path("cgi-bin", "token")
            parameters.apply {
                append("grant_type", "client_credential")
                append("appid", appId)
                append("secret", appSecret)
            }
        }
    }
    val responseBody = response.body<WeixinAccessTokenResponse>()
    return responseBody.access_token
}


