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
package org.lumina.utils.security

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.lumina.fields.GeneralFields.WEIXIN_MP_SERVER_OPEN_API_HOST
import org.lumina.utils.commonClient
import org.lumina.utils.getWeixinAccessTokenOrNull
import org.lumina.utils.security.WeixinContentSecurityScene.SCENE_COMMENT
import org.lumina.utils.security.WeixinContentSecurityScene.SCENE_FORUM
import org.lumina.utils.security.WeixinContentSecurityScene.SCENE_PROFILE
import org.lumina.utils.security.WeixinContentSecurityScene.SCENE_SOCIAL_LOG
import java.security.InvalidParameterException

/**
 * 场景枚举值
 *
 * @property SCENE_PROFILE 资料
 * @property SCENE_COMMENT 评论
 * @property SCENE_FORUM 论坛
 * @property SCENE_SOCIAL_LOG 社交日志
 */
object WeixinContentSecurityScene {
    const val SCENE_PROFILE = 1 // 资料
    const val SCENE_COMMENT = 2 // 评论
    const val SCENE_FORUM = 3 // 论坛
    const val SCENE_SOCIAL_LOG = 4 // 社交日志
}

/**
 * 微信小程序内容安全请求体
 *
 * @property content 需检测的文本内容，文本字数的上限为2500字，需使用UTF-8编码
 * @property version 接口版本号，2.0版本为固定值2
 * @property scene 场景枚举值（1 资料；2 评论；3 论坛；4 社交日志）
 * @property openid 用户的openid（用户需在近两小时访问过小程序）
 * @property title 文本标题，需使用UTF-8编码
 * @property nickname 用户昵称，需使用UTF-8编码
 * @property signature 个性签名，该参数仅在资料类场景有效(scene=1)，需使用UTF-8编码
 * @see [微信开放文档](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/sec-center/sec-check/msgSecCheck.html)
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class WeixinContentSecurityRequest(
    val content: String,
    @EncodeDefault val version: Int = 2,
    @EncodeDefault val scene: Int = SCENE_FORUM,
    val openid: String,
    val title: String? = null,
    val nickname: String? = null,
    val signature: String? = null
) {
    init {
        if (scene != SCENE_PROFILE && signature != null) throw InvalidParameterException("个性签名只允许在资料场景使用")
    }
}

/**
 * 微信小程序内容安全响应体
 *
 * @property errcode 错误码
 * @property errmsg 错误信息
 * @property detail 详细检测结果
 * @property trace_id 唯一请求标识，标记单次请求
 * @property result 综合结果
 * @see [微信开放文档](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/sec-center/sec-check/msgSecCheck.html)
 */
@Serializable
data class WeixinContentSecurityResponse(
    val errcode: Int? = null,
    val errmsg: String? = null,
    val detail: List<WeixinContentSecurityResponseDetail>? = null,
    val trace_id: String? = null,
    val result: WeixinContentSecurityResponseResult? = null
)

/**
 * 详细检测结果
 *
 * @property strategy 策略类型
 * @property errcode 错误码，仅当该值为0时，该项结果有效
 * @property suggest 建议，有risky、pass、review三种值
 * @property label 命中标签枚举值，100 正常；10001 广告；20001 时政；20002 色情；20003 辱骂；20006 违法犯罪；20008 欺诈；20012 低俗；20013 版权；21000 其他
 * @property keyword 命中的自定义关键词
 * @property prob 0-100，代表置信度，越高代表越有可能属于当前返回的标签（label）
 */
@Serializable
data class WeixinContentSecurityResponseDetail(
    val strategy: String? = null,
    val errcode: Int? = null,
    val suggest: String? = null,
    val label: Int? = null,
    val keyword: String? = null,
    val prob: Int? = null
)

/**
 * 综合结果
 *
 * @property suggest 建议，有risky、pass、review三种值
 * @property label 命中标签枚举值，100 正常；10001 广告；20001 时政；20002 色情；20003 辱骂；20006 违法犯罪；20008 欺诈；20012 低俗；20013 版权；21000 其他
 */
@Serializable
data class WeixinContentSecurityResponseResult(
    val suggest: String? = null, val label: Int? = null
)

private val json = Json { ignoreUnknownKeys = true }

/**
 * 调用微信内容安全检测接口
 *
 * @param appId 小程序 appId
 * @param appSecret 小程序 appSecret
 * @throws IllegalStateException 如果获取微信接口调用凭证失败
 * @throws IllegalArgumentException 如果个性签名在资料场景下被使用
 * @see [微信开放文档](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/sec-center/sec-check/msgSecCheck.html)
 */
suspend fun weixinContentSecurityCheck(
    appId: String, appSecret: String, request: WeixinContentSecurityRequest
): WeixinContentSecurityResponse {
    val accessToken =
        getWeixinAccessTokenOrNull(appId, appSecret) ?: throw IllegalStateException("获取微信接口调用凭证失败")
    val response = commonClient.post {
        url {
            protocol = URLProtocol.HTTPS
            host = WEIXIN_MP_SERVER_OPEN_API_HOST
            path("wxa", "msg_sec_check")
            parameters.append("access_token", accessToken)
        }
        contentType(ContentType.Application.Json)
        setBody(request)
    }
    return json.decodeFromString<WeixinContentSecurityResponse>(response.bodyAsText())
}

/**
 * 临时性策略检查内容安全
 * 在微信侧返回建议为 pass 或 review 时认为内容（相对来说）安全
 */
suspend fun temporaryWeixinContentSecurityCheck(
    appId: String, appSecret: String, request: WeixinContentSecurityRequest
): Boolean {
    val result = weixinContentSecurityCheck(appId, appSecret, request)
    val suggest = result.result?.suggest ?: throw IllegalStateException("获取微信内容安全检测结果失败")
    return suggest == "pass" || suggest == "review"
}