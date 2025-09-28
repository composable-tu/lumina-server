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
package org.lumina.routes.subroutes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.jdbc.update
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_SOTER
import org.lumina.fields.ReturnInvalidReasonFields.USER_NOT_FOUND
import org.lumina.models.Users
import org.lumina.utils.LuminaAuthenticationException
import org.lumina.utils.LuminaBadRequestException
import org.lumina.utils.security.SoterResultFromUser
import org.lumina.utils.security.WeixinSoterCheckRequest
import org.lumina.utils.security.weixinSoterCheck

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
                if (!isSoterPassed) throw LuminaAuthenticationException(INVALID_SOTER)
                transaction {
                    val userRow = Users.selectAll().where { Users.weixinOpenId eq weixinOpenId }.firstOrNull()
                        ?: throw LuminaBadRequestException(USER_NOT_FOUND)
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