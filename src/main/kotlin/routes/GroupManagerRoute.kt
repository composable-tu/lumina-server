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
package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.jdbc.update
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_GROUP_ID
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.UNSAFE_CONTENT
import org.lumina.models.Groups
import org.lumina.models.UserGroups
import org.lumina.models.UserRole
import org.lumina.utils.LuminaNotFoundException
import org.lumina.utils.normalized
import org.lumina.utils.security.*
import org.lumina.utils.security.RuntimePermission.SUPER_ADMIN
import org.lumina.utils.sm3
import java.time.LocalDateTime

/**
 * 团体管理路由
 *
 * 功能：
 * - 更改团体名
 * - 移除成员
 * - 为团体设置临时密码与有效期（直接覆盖之前的设定）
 * - 将成员设置为管理员（非超管）
 * - 将管理员（非超管）设置为普通成员
 */
fun Route.groupManagerRoute(appId: String, appSecret: String) {
    authenticate {
        route("/groupManager/{groupId}") {

            // 更改团体名
            post("/rename") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupRenameRequest>().normalized()
                val isContentSafety = temporaryWeixinContentSecurityCheck(
                    appId, appSecret, WeixinContentSecurityRequest(
                        content = request.newGroupName,
                        nickname = request.newGroupName,
                        scene = WeixinContentSecurityScene.SCENE_PROFILE,
                        openid = weixinOpenId,
                    )
                )
                if (!isContentSafety) return@post call.respond(
                    HttpStatusCode.BadRequest, UNSAFE_CONTENT
                )
                protectedRoute(
                    weixinOpenId,
                    groupId,
                    SUPERADMIN_ADMIN_SET,
                    CheckType.GROUP_ID,
                    "更改团体名",
                    true,
                    request.soterInfo
                ) {
                    transaction {
                        val group = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                        if (group == null) throw LuminaNotFoundException("群组不存在")
                        Groups.update({ Groups.groupId eq groupId }) {
                            it[Groups.groupName] = request.newGroupName
                        }
                    }
                    call.respond("群组名称修改成功")
                }
            }

            // 移除成员
            // TODO：信息加密
            post("/removeMember") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized()
                protectedRoute(
                    weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, "移除成员", true, request.soterInfo
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
                    if (conflictUserList.isNullOrEmpty() && noPermissionUserList.isNullOrEmpty()) call.respond("用户移除成功") else {
                        val responseText =
                            "其他成员已移除。" + if (!conflictUserList.isNullOrEmpty()) "以下成员在团体中未找到：${
                                conflictUserList.joinToString("、") { it.userId }
                            }。" else "" + if (!noPermissionUserList.isNullOrEmpty()) "以下成员是管理员，需要先将其设置为普通成员再移除：${
                                noPermissionUserList.joinToString("、") { it.userId }
                            }。" else ""
                        call.respond(
                            HttpStatusCode.NotFound, responseText
                        )
                    }
                }
            }

            // 为团体设置预授权凭证与有效期
            // TODO：信息加密
            post("/setPreAuthToken") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<SetGroupPreAuthTokenRequest>().normalized()
                val preAuthToken = request.preAuthToken
                val isContentSafety = temporaryWeixinContentSecurityCheck(
                    appId, appSecret, WeixinContentSecurityRequest(
                        content = preAuthToken,
                        scene = WeixinContentSecurityScene.SCENE_COMMENT,
                        openid = weixinOpenId,
                    )
                )
                if (!isContentSafety) return@post call.respond(
                    HttpStatusCode.BadRequest, UNSAFE_CONTENT
                )
                if (request.validity <= 0) call.respond(HttpStatusCode.BadRequest, "请输入正确的有效期")
                val endDateTime = LocalDateTime.now().plusMinutes(request.validity)
                protectedRoute(
                    weixinOpenId,
                    groupId,
                    SUPERADMIN_ADMIN_SET,
                    CheckType.GROUP_ID,
                    "为团体设置预授权凭证与有效期",
                    true,
                    request.soterInfo
                ) {
                    transaction {
                        Groups.update({ Groups.groupId eq groupId }) {
                            it[groupPreAuthTokenSM3] = preAuthToken.sm3()
                            it[preAuthTokenEndTime] = endDateTime
                        }
                    }
                    call.respond("团体预授权凭证设置成功")
                }
            }

            // 将成员设置为管理员
            // TODO：信息加密
            post("/setAdmin") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized()
                protectedRoute(
                    weixinOpenId,
                    groupId,
                    setOf(SUPER_ADMIN),
                    CheckType.GROUP_ID,
                    "将成员设置为管理员",
                    true,
                    request.soterInfo
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
                    if (conflictUserList.isNullOrEmpty() && noPermissionUserList.isNullOrEmpty()) call.respond("设置管理员成功") else {
                        val responseText =
                            "其他成员设置管理员成功。" + if (!conflictUserList.isNullOrEmpty()) "以下成员在团体中未找到：${
                                conflictUserList.joinToString("、") { it.userId }
                            }。" else "" + if (!noPermissionUserList.isNullOrEmpty()) "以下成员已不是不同成员：${
                                noPermissionUserList.joinToString("、") { it.userId }
                            }。" else ""
                        call.respond(
                            HttpStatusCode.NotFound, responseText
                        )
                    }
                }
            }

            // 将管理员（非超管）设置为普通成员
            // TODO：信息加密
            post("/resetToMember") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupManagerRequest>().normalized()
                protectedRoute(
                    weixinOpenId,
                    groupId,
                    setOf(SUPER_ADMIN),
                    CheckType.GROUP_ID,
                    "将管理员（非超管）设置为普通成员",
                    true,
                    request.soterInfo
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
                    if (conflictUserList.isNullOrEmpty() && noPermissionUserList.isNullOrEmpty()) call.respond(message = "取消管理员成功") else {
                        val responseText =
                            "其他成员取消管理员成功。" + if (!conflictUserList.isNullOrEmpty()) "以下成员在团体中未找到：${
                                conflictUserList.joinToString("、") { it.userId }
                            }。" else "" + if (!noPermissionUserList.isNullOrEmpty()) "以下成员不是普通管理员：${
                                noPermissionUserList.joinToString("、") { it.userId }
                            }。" else ""
                        call.respond(
                            HttpStatusCode.NotFound, responseText
                        )
                    }
                }
            }
        }
    }
}


@Serializable
data class GroupManagerUser(
    val userId: String, val userName: String? = null
)

/**
 * 团体重命名
 * @property newGroupName 新的团体名称
 * @property soterInfo SOTER 生物验证信息
 */
@Serializable
private data class GroupRenameRequest(
    val newGroupName: String, val soterInfo: SoterResultFromUser? = null
)

@Serializable
private data class GroupManagerRequest(
    val groupManageUserList: List<GroupManagerUser>, val soterInfo: SoterResultFromUser? = null
)

/**
 * 设置团体预授权凭证
 * @property preAuthToken 预授权凭证
 * @property validity 预授权凭证有效期（整数，单位为分钟）
 * @property soterInfo SOTER 生物验证信息
 */
@Serializable
private data class SetGroupPreAuthTokenRequest(
    val preAuthToken: String, val validity: Long, val soterInfo: SoterResultFromUser? = null
)

@Serializable
private data class GroupManagerResponse(
    val conflictUserList: List<GroupManagerUser>? = null, val noPermissionUserList: List<GroupManagerUser>? = null
)
