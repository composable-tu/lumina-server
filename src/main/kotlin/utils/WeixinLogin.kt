/**
 * Copyright (c) 2025 LuminaPJ
 * SM2 Key Generator is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
package org.lumina.utils

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.lumina.fields.GeneralFields.WEIXIN_MP_SERVER_OPEN_API_HOST
import org.lumina.models.Users

private val json = Json { ignoreUnknownKeys = true }

suspend fun code2Session(appId: String, appSecret: String, code: String): WeixinLoginResponse {
    val response = commonClient.get {
        url {
            protocol = URLProtocol.HTTPS
            host = WEIXIN_MP_SERVER_OPEN_API_HOST
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

@Serializable
data class WeixinLoginResponse(
    val openid: String? = null,
    val session_key: String? = null,
    val unionid: String? = null,
    val errcode: Int? = null,
    val errmsg: String? = null
)

/**
 * 将微信小程序用户登录临时凭证转为微信小程序用户登录信息，包括 Open ID（如果转换失败则返回 Null）
 */
suspend fun code2WeixinOpenIdOrNull(appId: String, appSecret: String, code: String) =
    code2Session(appId, appSecret, code)

/**
 * 从数据库中获取微信小程序用户 ID（如果转换失败则返回 Null）
 */
fun Transaction.getUserIdByWeixinOpenIdOrNullFromDB(openId: String): String? {
    val user = Users.selectAll().where { Users.weixinOpenId eq openId }.firstOrNull()
    return user?.get(Users.userId)
}
