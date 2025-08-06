package org.lumina.utils

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.lumina.fields.GeneralFields.WEIXIN_MP_SERVER_OPEN_API_HOST

private val json = Json { ignoreUnknownKeys = true }

/**
 * 在内存中缓存的微信接口调用凭据
 */
private var cachedAccessToken: String? = null

/**
 * 在内存中缓存的微信接口调用凭据过期时间戳，需从服务器返回的 expires_in 字段中获取有效时长并计算出过期时间
 */
private var tokenExpiryTime: Long = 0L

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

private val client = HttpClient(CIO) {
    install(ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true })
    }
}
private val tokenMutex = Mutex()

/**
 * 获取接口调用凭据，凭据字符串优先来自内存缓存
 *
 * @param appId 小程序 appId
 * @param appSecret 小程序 appSecret
 * @return 接口调用凭据或 null
 * @see [微信开放文档](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/mp-access-token/getAccessToken.html)
 */
suspend fun getWeixinAccessTokenOrNull(appId: String, appSecret: String): String? = tokenMutex.withLock {
    val now = System.currentTimeMillis()
    if (cachedAccessToken != null && now < tokenExpiryTime) return cachedAccessToken

    val response = client.get {
        url {
            protocol = URLProtocol.HTTPS
            host = WEIXIN_MP_SERVER_OPEN_API_HOST
            path("cgi-bin", "token")
            parameters.apply {
                append("grant_type", "client_credential")
                append("appid", appId)
                append("secret", appSecret)
            }
        }
    }
    val responseBody = json.decodeFromString<WeixinAccessTokenResponse>(response.bodyAsText())
    val token = responseBody.access_token
    val expiresIn = responseBody.expires_in
    tokenExpiryTime = if (expiresIn != null) now + expiresIn * 1000L else 0L
    cachedAccessToken = token
    return token
}


