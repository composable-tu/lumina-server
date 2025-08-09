package org.lumina.routes.data

import kotlinx.serialization.Serializable

/**
 * 经过中国商密 SM4 加密的前端请求内容，解密后才是正常请求信息
 */
@Serializable
data class EncryptContentRequest(
    val encryptContent: String,
    val encryptVersion: Int,
    val weixinLoginCode: String,
)