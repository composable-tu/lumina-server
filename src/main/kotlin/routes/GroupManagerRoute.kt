package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.SqlExpressionBuilder.eq
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.jdbc.update
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_GROUP_ID
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.models.Groups
import org.lumina.models.UserGroups
import org.lumina.models.UserRole
import org.lumina.utils.*
import org.lumina.utils.RuntimePermission.SUPER_ADMIN
import java.time.LocalDateTime

/**
 * 团体管理路由
 *
 * 功能：
 * - 移除成员
 * - 为团体设置临时密码与有效期（直接覆盖之前的设定）
 * - 将成员设置为管理员
 * - 将管理员（非超管）设置为普通成员
 */
fun Route.groupManagerRoute(appId: String, appSecret: String) {
    authenticate {
        route("/groupManager/{groupId}") {
            post("/remove") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized() as? GroupManagerRequest
                    ?: return@post call.respond(HttpStatusCode.BadRequest, "请求格式错误")
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
                    if (conflictUserList.isNullOrEmpty() && noPermissionUserList.isNullOrEmpty()) call.respond("用户移除成功") else call.respond(
                        HttpStatusCode.NotFound, Json.encodeToString<GroupManagerResponse>(groupManagerResponse)
                    )
                }
            }
            post("/setPassword") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<SetGroupPasswordRequest>().normalized() as? SetGroupPasswordRequest
                    ?: return@post call.respond(HttpStatusCode.BadRequest, "请求格式错误")
                val password = request.password
                val isContentSafety = temporaryWeixinContentSecurityCheck(
                    appId, appSecret, WeixinContentSecurityRequest(
                        content = password,
                        scene = WeixinContentSecurityScene.SCENE_COMMENT,
                        openid = weixinOpenId,
                    )
                )
                if (!isContentSafety) return@post call.respond(
                    HttpStatusCode.BadRequest, "您提交的内容被微信判定为存在违规内容，请修改后再次提交"
                )
                if (request.validity <= 0) call.respond(HttpStatusCode.BadRequest, "请输入正确的有效期")
                val endDateTime = LocalDateTime.now().plusMinutes(request.validity)
                protectedRoute(
                    weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, true, request.soterInfo
                ) {
                    transaction {
                        Groups.update({ Groups.groupId eq groupId }) {
                            it[entryPasswordSM3] = password.sm3()
                            it[passwordEndTime] = endDateTime
                        }
                    }
                    call.respond("临时密码设置成功")
                }
            }
            post("/setAdmin") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized() as? GroupManagerRequest
                    ?: return@post call.respond(HttpStatusCode.BadRequest, "请求格式错误")
                protectedRoute(
                    weixinOpenId, groupId, setOf(SUPER_ADMIN), CheckType.GROUP_ID, true, request.soterInfo
                ) {
                    val groupManagerResponse: GroupManagerResponse = transaction {
                        val groupSetAdminUserList = request.groupManageUserList
                        val notFoundUserList = mutableListOf<GroupManagerUser>()
                        val noPermissionUserList = mutableListOf<GroupManagerUser>()
                        groupSetAdminUserList.forEach { groupSetAdminUser ->
                            val setAdminUserId = groupSetAdminUser.userId
                            val userFromGroupDB = UserGroups.selectAll().where {
                                (UserGroups.userId eq setAdminUserId) and (UserGroups.groupId eq groupId)
                            }.firstOrNull()
                            if (userFromGroupDB != null && userFromGroupDB[UserGroups.permission] == UserRole.MEMBER) {
                                UserGroups.update({
                                    (UserGroups.userId eq setAdminUserId) and (UserGroups.groupId eq groupId)
                                }) {
                                    it[UserGroups.permission] = UserRole.ADMIN
                                }
                            } else if (userFromGroupDB == null) notFoundUserList.add(groupSetAdminUser) else if (userFromGroupDB[UserGroups.permission] != UserRole.MEMBER) noPermissionUserList.add(
                                groupSetAdminUser
                            )
                        }
                        GroupManagerResponse(notFoundUserList.toList(), noPermissionUserList.toList())
                    }
                    val conflictUserList = groupManagerResponse.conflictUserList
                    val noPermissionUserList = groupManagerResponse.noPermissionUserList
                    if (conflictUserList.isNullOrEmpty() && noPermissionUserList.isNullOrEmpty()) call.respond("设置管理员成功") else call.respond(
                        HttpStatusCode.NotFound, Json.encodeToString<GroupManagerResponse>(groupManagerResponse)
                    )
                }
            }
            post("/resetToMember") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized() as? GroupManagerRequest
                    ?: return@post call.respond(HttpStatusCode.BadRequest, "请求格式错误")
                protectedRoute(
                    weixinOpenId, groupId, setOf(SUPER_ADMIN), CheckType.GROUP_ID, true, request.soterInfo
                ) {
                    val groupManagerResponse: GroupManagerResponse = transaction {
                        val groupResetToMemberUserList = request.groupManageUserList
                        val notFoundUserList = mutableListOf<GroupManagerUser>()
                        val noPermissionUserList = mutableListOf<GroupManagerUser>()
                        groupResetToMemberUserList.forEach { groupResetToMemberUser ->
                            val setAdminUserId = groupResetToMemberUser.userId
                            val userFromGroupDB = UserGroups.selectAll().where {
                                (UserGroups.userId eq setAdminUserId) and (UserGroups.groupId eq groupId)
                            }.firstOrNull()
                            if (userFromGroupDB != null && userFromGroupDB[UserGroups.permission] == UserRole.ADMIN) {
                                UserGroups.update({
                                    (UserGroups.userId eq setAdminUserId) and (UserGroups.groupId eq groupId)
                                }) {
                                    it[UserGroups.permission] = UserRole.MEMBER
                                }
                            } else if (userFromGroupDB == null) notFoundUserList.add(groupResetToMemberUser) else if (userFromGroupDB[UserGroups.permission] != UserRole.ADMIN) noPermissionUserList.add(
                                groupResetToMemberUser
                            )
                        }
                        GroupManagerResponse(notFoundUserList.toList(), noPermissionUserList.toList())
                    }
                    val conflictUserList = groupManagerResponse.conflictUserList
                    val noPermissionUserList = groupManagerResponse.noPermissionUserList
                    if (conflictUserList.isNullOrEmpty() && noPermissionUserList.isNullOrEmpty()) call.respond(message = "取消管理员成功") else call.respond(
                        HttpStatusCode.NotFound, Json.encodeToString<GroupManagerResponse>(groupManagerResponse)
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
private data class GroupManagerRequest(
    val groupManageUserList: List<GroupManagerUser>, val soterInfo: SoterResultFromUser? = null
)

/**
 * 设置群聊临时密码
 * @property password 临时密码
 * @property validity 临时密码有效期（整数，单位为分钟）
 * @property soterInfo SOTER 生物验证信息
 */
@Serializable
private data class SetGroupPasswordRequest(
    val password: String, val validity: Long, val soterInfo: SoterResultFromUser? = null
)

@Serializable
private data class GroupManagerResponse(
    val conflictUserList: List<GroupManagerUser>? = null, val noPermissionUserList: List<GroupManagerUser>? = null
)
