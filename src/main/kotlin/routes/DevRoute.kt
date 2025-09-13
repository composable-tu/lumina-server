package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.utils.normalized
import org.lumina.utils.security.EncryptContentRequest
import org.lumina.utils.security.WeixinUserCryptoKeyRequest
import org.lumina.utils.security.weixinDecryptContent

/**
 * 调试环境路由，生产环境下不集成
 *
 * 功能：
 * - 获取当前登录用户的 weixinOpenId
 * - 解密用户端发送的字符串
 */
fun Routing.devRoute(appId: String, appSecret: String) {
    route("/dev") {
        authenticate {
            get("/weixinOpenId") {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                call.respond(weixinOpenId)
            }
            post("/decryptString") {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<EncryptContentRequest>().normalized()
                val weixinUserCryptoKeyRequest = WeixinUserCryptoKeyRequest(
                    weixinOpenId,
                    request.encryptContent,
                    request.encryptVersion,
                    request.hmacSignature,
                    request.weixinLoginCode
                )
                val decryptedString = weixinDecryptContent(appId, appSecret, weixinUserCryptoKeyRequest)
                call.respond(decryptedString)
            }
        }
    }
}
