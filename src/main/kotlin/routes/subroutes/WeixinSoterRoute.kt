package org.lumina.routes.subroutes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.h2.security.auth.AuthConfigException
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.jdbc.update
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_SOTER
import org.lumina.fields.ReturnInvalidReasonFields.USER_NOT_FOUND
import org.lumina.models.Users
import org.lumina.utils.SoterResultFromUser
import org.lumina.utils.WeixinSoterCheckRequest
import org.lumina.utils.weixinSoterCheck
import javax.security.sasl.AuthenticationException

/**
 * Soter 路由
 *
 * 功能：
 * - 检查用户是否开启 Soter 生物认证保护功能
 * - 开启 Soter 生物认证保护
 * - 关闭 Soter 生物认证保护
 */
fun Routing.weixinSoterRoute(appId: String, appSecret: String) {
    route("/soter") {
        authenticate {
            get("/check") {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val isUserSoterEnabled = transaction {
                    val userRow = Users.selectAll().where { Users.weixinOpenId eq weixinOpenId }.firstOrNull()
                        ?: return@transaction false
                    return@transaction userRow[Users.isSoterEnabled]
                }
                call.respond(WeixinSoterCheckResponse(isUserSoterEnabled))
            }
            post("/action") {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<WeixinSoterActionRequest>()
                val isSoterPassed = weixinSoterCheck(
                    appId, appSecret, WeixinSoterCheckRequest(
                        weixinOpenId, request.soterInfo.json_string, request.soterInfo.json_signature
                    )
                )
                if (!isSoterPassed) throw AuthenticationException(INVALID_SOTER)
                transaction {
                    val userRow = Users.selectAll().where { Users.weixinOpenId eq weixinOpenId }.firstOrNull()
                        ?: throw AuthConfigException(USER_NOT_FOUND)
                    Users.update({ Users.userId eq userRow[Users.userId] }) {
                        it[isSoterEnabled] = when (request.action) {
                            SoterAction.ENABLE -> true
                            SoterAction.DISABLE -> false
                        }
                    }
                }
                call.respond(HttpStatusCode.OK)
            }
        }
    }
}

@Serializable
private enum class SoterAction(val value: String) {
    @SerialName("enable")
    ENABLE("enable"),

    @SerialName("disable")
    DISABLE("disable");
}

@Serializable
private data class WeixinSoterCheckResponse(
    val isUserSoterEnabled: Boolean
)

@Serializable
private data class WeixinSoterActionRequest(
    val action: SoterAction, val soterInfo: SoterResultFromUser
)