package org.linlangwen.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.linlangwen.models.UserGroups
import org.linlangwen.models.UserRole
import org.linlangwen.models.Users
import org.linlangwen.utils.*

fun Route.groupManagerRoute(appId: String, appSecret: String) {
    authenticate {
        route("/groupManager/{groupId}") {
            post("/add") {
                val groupId = call.parameters["groupId"] ?: return@post call.respondText(
                    status = HttpStatusCode.BadRequest, text = "无效的团体 ID"
                )
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@post call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val request = call.receive<GroupManagerRequest>()
                val groupAddUserList = request.groupManageUserList
                groupAddUserList.forEach { groupAddUser ->
                    val isContentSafety = temporaryWeixinContentSecurityCheck(
                        appId, appSecret, WeixinContentSecurityRequest(
                            content = groupAddUser.userName!! + groupAddUser.userId,
                            scene = WeixinContentSecurityScene.SCENE_PROFILE,
                            openid = weixinOpenId,
                            nickname = groupAddUser.userName
                        )
                    )
                    if (!isContentSafety) return@post call.respondText("您提交的内容被微信判定为存在违规内容，请修改后再次提交")
                }
                protectedRoute(
                    weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, true, request.soterInfo
                ) {
                    val repeatUserList = transaction {
                        val repeatUserList = mutableListOf<GroupManagerUser>()
                        groupAddUserList.forEach { groupAddUser ->
                            val addUserId = groupAddUser.userId
                            val addUserName = groupAddUser.userName
                            val userFromGroupDB = UserGroups.selectAll().where {
                                (UserGroups.userId eq addUserId) and (UserGroups.groupId eq groupId)
                            }.firstOrNull()
                            if (userFromGroupDB != null) repeatUserList.add(groupAddUser) else {
                                Users.insert {
                                    it[Users.userId] = addUserId
                                    if (addUserName != null) it[Users.userName] = addUserName
                                }
                                UserGroups.insert {
                                    it[UserGroups.userId] = addUserId
                                    it[UserGroups.groupId] = groupId
                                    it[UserGroups.permission] = UserRole.MEMBER
                                }
                            }
                        }
                        repeatUserList.toList()
                    }
                    if (repeatUserList.isNotEmpty()) {
                        val respose = GroupManagerResponse(repeatUserList)
                        call.respond(
                            status = HttpStatusCode.Conflict, Json.encodeToString<GroupManagerResponse>(respose)
                        )
                    } else call.respond(HttpStatusCode.OK, message = "用户添加成功")
                }

            }
            post("/remove") {
                val groupId = call.parameters["groupId"] ?: return@post call.respondText(
                    status = HttpStatusCode.BadRequest, text = "无效的团体 ID"
                )
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@post call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val request = call.receive<GroupManagerRequest>()
                protectedRoute(
                    weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, true, request.soterInfo
                ) {
                    val groupManagerResponse: GroupManagerResponse = transaction {
                        val groupRemoveUserList = request.groupManageUserList
                        val notFoundUserList = mutableListOf<GroupManagerUser>()
                        val noPremissionUserList = mutableListOf<GroupManagerUser>()
                        groupRemoveUserList.forEach { groupRemoveUser ->
                            val removeUserId = groupRemoveUser.userId
                            val userFromGroupDB = UserGroups.selectAll().where {
                                (UserGroups.userId eq removeUserId) and (UserGroups.groupId eq groupId)
                            }.firstOrNull()
                            if (userFromGroupDB != null && userFromGroupDB[UserGroups.permission] == UserRole.MEMBER) {
                                UserGroups.deleteWhere {
                                    (UserGroups.userId eq removeUserId) and (UserGroups.groupId eq groupId)
                                }
                            } else if (userFromGroupDB == null) notFoundUserList.add(groupRemoveUser) else if (userFromGroupDB[UserGroups.permission] != UserRole.MEMBER) noPremissionUserList.add(
                                groupRemoveUser
                            )
                        }
                        GroupManagerResponse(notFoundUserList.toList(), noPremissionUserList.toList())
                    }
                    val conflictUserList = groupManagerResponse.conflictUserList
                    val noPremissionUserList = groupManagerResponse.noPremissionUserList
                    if (conflictUserList.isNullOrEmpty() && noPremissionUserList.isNullOrEmpty()) call.respond(
                        HttpStatusCode.OK, message = "用户移除成功"
                    ) else call.respond(
                        status = HttpStatusCode.NotFound,
                        Json.encodeToString<GroupManagerResponse>(groupManagerResponse)
                    )
                }
            }
        }
    }
}


@Serializable
data class GroupManagerUser(
    val userId: String, val userName: String? = null
)

@Serializable
data class GroupManagerRequest(
    val groupManageUserList: List<GroupManagerUser>, val soterInfo: SoterResultFromUser? = null
)

@Serializable
data class GroupManagerResponse(
    val conflictUserList: List<GroupManagerUser>? = null, val noPremissionUserList: List<GroupManagerUser>? = null
)
