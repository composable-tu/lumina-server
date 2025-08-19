package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.USER_NOT_FOUND
import org.lumina.models.Users
import org.lumina.utils.LuminaBadRequestException

fun Routing.userRoute(appId: String, appSecret: String) {
    route("/user") {
        authenticate {
            get {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val userInfo = transaction {
                    val userRow = Users.selectAll().where { Users.weixinOpenId eq weixinOpenId }.firstOrNull()
                        ?: throw LuminaBadRequestException(USER_NOT_FOUND)
                    UserInfo(userRow[Users.userId], userRow[Users.userName])
                }
                call.respond(userInfo)
            }
        }
    }
}

@Serializable
data class UserInfo(
    val userId: String, val userName: String? = null
)