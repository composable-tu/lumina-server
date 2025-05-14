package org.lumina.routes

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
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_GROUP_ID
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.models.UserGroups
import org.lumina.models.UserRole
import org.lumina.models.Users
import org.lumina.utils.*

/**
 * 团体管理路由
 *
 * 功能：
 * - 添加成员
 * - 移除成员
 * - TODO: 为团体设置临时密码与有效期
 */
fun Route.groupManagerRoute(appId: String, appSecret: String) {
    authenticate {
        route("/groupManager/{groupId}") {
            post("/add") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized() as GroupManagerRequest
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
                    if (!isContentSafety) return@post call.respond(
                        HttpStatusCode.BadRequest,
                        "您提交的内容被微信判定为存在违规内容，请修改后再次提交"
                    )
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
                        val response = GroupManagerResponse(repeatUserList)
                        call.respond(
                            HttpStatusCode.Conflict, Json.encodeToString<GroupManagerResponse>(response)
                        )
                    } else call.respond(HttpStatusCode.OK, "用户添加成功")
                }

            }
            post("/remove") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized() as GroupManagerRequest
                protectedRoute(
                    weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, true, request.soterInfo
                ) {
                    val groupManagerResponse: GroupManagerResponse = transaction {
                        val groupRemoveUserList = request.groupManageUserList
                        val notFoundUserList = mutableListOf<GroupManagerUser>()
                        val noPermissionUserList = mutableListOf<GroupManagerUser>()
                        groupRemoveUserList.forEach { groupRemoveUser ->
                            val removeUserId = groupRemoveUser.userId
                            val userFromGroupDB = UserGroups.selectAll().where {
                                (UserGroups.userId eq removeUserId) and (UserGroups.groupId eq groupId)
                            }.firstOrNull()
                            if (userFromGroupDB != null && userFromGroupDB[UserGroups.permission] == UserRole.MEMBER) {
                                UserGroups.deleteWhere {
                                    (UserGroups.userId eq removeUserId) and (UserGroups.groupId eq groupId)
                                }
                            } else if (userFromGroupDB == null) notFoundUserList.add(groupRemoveUser) else if (userFromGroupDB[UserGroups.permission] != UserRole.MEMBER) noPermissionUserList.add(
                                groupRemoveUser
                            )
                        }
                        GroupManagerResponse(notFoundUserList.toList(), noPermissionUserList.toList())
                    }
                    val conflictUserList = groupManagerResponse.conflictUserList
                    val noPermissionUserList = groupManagerResponse.noPermissionUserList
                    if (conflictUserList.isNullOrEmpty() && noPermissionUserList.isNullOrEmpty()) call.respond(
                        HttpStatusCode.OK, message = "用户移除成功"
                    ) else call.respond(
                        HttpStatusCode.NotFound,
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
    val conflictUserList: List<GroupManagerUser>? = null, val noPermissionUserList: List<GroupManagerUser>? = null
)
