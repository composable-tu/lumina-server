package org.lumina.utils.security

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.lumina.fields.GeneralFields.WEIXIN_MP_SERVER_OPEN_API_HOST
import org.lumina.utils.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private val json = Json { ignoreUnknownKeys = true }

/**
 * 使用中国商密 SM4 算法解密来自前端的加密请求
 *
 * 可有效防止中间人攻击，但非必要不使用。
 *
 * 由于服务端仅能获取用户的最近三次加密 Key，如果出现大量并发加密内容操作会导致服务端无法解密内容。
 *
 * 参考：[小程序加密网络通道](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/user-encryptkey.html)
 * @param appId 微信小程序 appId
 * @param appSecret 微信小程序 appSecret
 * @param request 微信用户数据解密需求信息
 * @return 解密后的字符串
 */
suspend fun weixinDecryptContent(appId: String, appSecret: String, request: WeixinUserCryptoKeyRequest): String {
    val accessToken =
        getWeixinAccessTokenOrNull(appId, appSecret) ?: throw IllegalStateException("获取微信接口调用凭证失败")
    val sessionKey = code2Session(appId, appSecret, request.weixinLoginCode).session_key ?: throw IllegalStateException(
        "获取微信用户会话密钥失败"
    )
    val signature = generateHmac(sessionKey)
    val weixinEncryptKeyList = getWeixinEncryptKey(accessToken, request.openid, signature).key_info_list
        ?: throw IllegalStateException("未找到对应的微信用户加密密钥")
    val currentWeixinEncryptKey = weixinEncryptKeyList.firstOrNull {
        it.version == request.encryptVersion
    } ?: throw IllegalStateException("未找到对应的微信用户加密密钥")
    if (currentWeixinEncryptKey.expire_in <= 0) throw IllegalStateException("微信用户加密密钥已过期")

    val iv = currentWeixinEncryptKey.iv
    val encryptKey = currentWeixinEncryptKey.encrypt_key
    val encryptKeyHex = encryptKey.base64KeyToHex()
    val sm3Iv = iv.sm3().substring(0, 32)

    val encryptKeyByteArray = encryptKeyHex.hexStringToByteArray()
    val secretKey = SecretKeySpec(encryptKeyByteArray, "SM4")
    val cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding")
    val paramSpec = IvParameterSpec(sm3Iv.hexStringToByteArray())

    cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec)
    val decrypted = cipher.doFinal(request.encryptContent.hexStringToByteArray())
    return String(decrypted)
}

suspend fun getWeixinEncryptKey(
    accessToken: String, weixinOpenId: String, signature: String
): WeixinUserCryptoKeyResponse {
    val response = commonClient.get {
        url {
            protocol = URLProtocol.HTTPS
            host = WEIXIN_MP_SERVER_OPEN_API_HOST
            path("wxa", "business", "getuserencryptkey")
            parameters.append("access_token", accessToken)
            parameters.append("openid", weixinOpenId)
            parameters.append("signature", signature)
            parameters.append("sig_method", "hmac_sha256")
        }
    }
    return json.decodeFromString<WeixinUserCryptoKeyResponse>(response.bodyAsText())
}

@Serializable
data class WeixinUserCryptoKeyRequest(
    val openid: String, val encryptContent: String, val encryptVersion: Int, val weixinLoginCode: String
)

@Serializable
data class WeixinUserCryptoKeyResponse(
    val errcode: Int? = null, val errmsg: String? = null, val key_info_list: List<WeixinUserCryptoKeyInfo>? = null
)

/**
 * 微信用户加密密钥
 * @param encrypt_key 加密密钥
 * @param version 加密密钥版本
 * @param expire_in 剩余有效时间
 * @param iv 加密密钥的初始向量
 * @param create_time 创建时间
 */
@Serializable
data class WeixinUserCryptoKeyInfo(
    val encrypt_key: String, val version: Int, val expire_in: Int, val iv: String, val create_time: Int
)

private fun String.hexStringToByteArray(): ByteArray {
    val data = ByteArray(length / 2)
    for (i in data.indices) {
        val hex = substring(i * 2, i * 2 + 2)
        data[i] = hex.toInt(16).toByte()
    }
    return data
}

private fun generateHmac(sessionKey: String): String {
    val algorithm = "HmacSHA256"
    val mac = Mac.getInstance(algorithm)
    val keyBytes = sessionKey.toByteArray(Charsets.UTF_8)
    val secretKey = SecretKeySpec(keyBytes, algorithm)
    mac.init(secretKey)
    mac.update(ByteArray(0))
    val digest = mac.doFinal()
    return bytesToHex(digest)
}

private fun bytesToHex(bytes: ByteArray): String {
    val hexChars = CharArray(bytes.size * 2)
    for (i in bytes.indices) {
        val v = bytes[i].toInt() and 0xFF
        hexChars[i * 2] = "0123456789abcdef"[v ushr 4]
        hexChars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
    }
    return String(hexChars)
}