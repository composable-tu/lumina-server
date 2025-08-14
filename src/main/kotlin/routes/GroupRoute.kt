package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.toKotlinLocalDateTime
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.core.SqlExpressionBuilder.eq
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_GROUP_ID
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.UNSAFE_CONTENT
import org.lumina.models.*
import org.lumina.utils.normalized
import org.lumina.utils.security.*
import org.lumina.utils.security.RuntimePermission.ADMIN
import org.lumina.utils.security.RuntimePermission.MEMBER
import org.lumina.utils.sm3
import java.time.LocalDateTime

/**
 * 团体路由
 *
 * 功能：
 * - 获取自己加入的团体
 * - 申请加入团体
 * - 退出团体
 * - 团体管理员、超管、成员获取团体信息
 */
fun Route.groupRoute(appId: String, appSecret: String) {
    authenticate {
        route("/group") {
            // 获取自己加入的团体
            get {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val joinedGroupList: List<JoinedGroupInfo> = transaction {
                    val userIdFromDB = weixinOpenId2UserIdOrNull(weixinOpenId) ?: return@transaction emptyList()
                    UserGroups.selectAll().where { UserGroups.userId eq userIdFromDB }.map {
                        val groupId = it[UserGroups.groupId]
                        val groupRow = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                        if (groupRow == null) throw Exception("服务端出现错误")
                        val groupName = groupRow[Groups.groupName]
                        val permission = it[UserGroups.permission]
                        JoinedGroupInfo(groupId, groupName, permission)
                    }
                }
                call.respond(joinedGroupList)
            }

            route("/{groupId}") {
                // 申请加入团体
                post("/join") {
                    val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                        HttpStatusCode.BadRequest, INVALID_GROUP_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    val weixinUnionId = call.principal<JWTPrincipal>()?.get("weixinUnionId")?.trim()
                    val request = call.receive<GroupJoinRequest>().normalized() as GroupJoinRequest
                    val requesterUserId = request.requesterUserId
                    val requesterUserName = request.requesterUserName
                    val requesterComment = request.requesterComment
                    val requesterDevice = request.requesterDevice
                    val groupPreAuthToken = request.groupPreAuthToken
                    val userIdFromDB = transaction {
                        val userIdFromDB = weixinOpenId2UserIdOrNull(weixinOpenId)
                        if (userIdFromDB != null) {
                            if (userIdFromDB != requesterUserId) throw BadRequestException("您的微信账号似乎曾绑定过用户 ID，但现在您填入的用户 ID 与数据库中您微信绑定的用户 ID 不一致。如需更改用户 ID，请联系客服进行处理。")
                            if (isUserInGroup(userIdFromDB, groupId)) throw BadRequestException("您已加入该团体")
                        }

                        if (!isGroupCreated(groupId)) throw IllegalArgumentException("该团体不存在")

                        // 验证此前是否有同团体号下待审批的申请
                        if (groupPreAuthToken.isNullOrEmpty()) {
                            val joinGroupApprovalRows = JoinGroupApprovals.selectAll()
                                .where { (JoinGroupApprovals.requesterWeixinOpenId eq weixinOpenId) and (JoinGroupApprovals.targetGroupId eq groupId) }
                            joinGroupApprovalRows.forEach { joinGroupApprovalRow ->
                                val approvalId = joinGroupApprovalRow[JoinGroupApprovals.approvalId]
                                val approvalRow =
                                    Approvals.selectAll().where { Approvals.approvalId eq approvalId }.firstOrNull()
                                if (approvalRow == null) throw Exception("服务端出现错误")
                                if (approvalRow[Approvals.status] == ApprovalStatus.PENDING) throw BadRequestException("您此前已提交过申请，请等待审批")
                            }
                        }
                        userIdFromDB
                    }

                    val weixinContentSecurityCheck = temporaryWeixinContentSecurityCheck(
                        appId, appSecret, WeixinContentSecurityRequest(
                            content = requesterComment ?: requesterUserName,
                            scene = WeixinContentSecurityScene.SCENE_PROFILE,
                            openid = weixinOpenId,
                            title = requesterUserId,
                            nickname = requesterUserName
                        )
                    )
                    if (!weixinContentSecurityCheck) throw BadRequestException(UNSAFE_CONTENT)
                    val isJoin = transaction {
                        // 这里的判断逻辑是，如果进团体临时令牌没写就认为是应该经过审批加入请求，进入审批数据库
                        // 如果进团体预授权凭证不符合数据库设置则直接打回，请求不进入数据库
                        // 如果预授权凭证正确则直接进团体
                        val preAuthTokenSM3 = if (groupPreAuthToken.isNullOrEmpty()) null else groupPreAuthToken.sm3()
                        val groupPreAuthTokenIsOk = if (groupPreAuthToken.isNullOrEmpty()) false else {
                            val groupRow = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                            if (groupRow == null) throw Exception("服务端出现错误")
                            val groupPreAuthTokenSM3 = groupRow[Groups.groupPreAuthTokenSM3]
                            if (preAuthTokenSM3 != groupPreAuthTokenSM3) {
                                throw BadRequestException("预授权凭证错误")
                            } else {
                                val groupPreAuthTokenEndTime = groupRow[Groups.preAuthTokenEndTime]
                                groupPreAuthTokenEndTime != null && groupPreAuthTokenEndTime >= LocalDateTime.now()
                            }
                        }

                        if (userIdFromDB == null) Users.insert {
                            it[this.userId] = requesterUserId
                            it[this.weixinOpenId] = weixinOpenId
                            if (weixinUnionId != null) it[this.weixinUnionId] = weixinUnionId
                            it[this.userName] = requesterUserName
                        }
                        val approvalId = Approvals.insert {
                            it[this.approvalType] = ApprovalTargetType.GROUP_JOIN
                            it[this.status] =
                                if (groupPreAuthTokenIsOk) ApprovalStatus.AUTO_PASSED else ApprovalStatus.PENDING
                            it[this.createdAt] = LocalDateTime.now()
                            it[this.comment] = requesterComment
                        }[Approvals.approvalId]
                        JoinGroupApprovals.insert {
                            it[this.approvalId] = approvalId
                            it[this.targetGroupId] = groupId
                            it[this.requesterUserId] = requesterUserId
                            it[this.requesterUserName] = requesterUserName
                            it[this.requesterDevice] = requesterDevice
                            it[this.requesterWeixinOpenId] = weixinOpenId
                            if (!groupPreAuthToken.isNullOrEmpty()) it[this.preAuthTokenSM3] = preAuthTokenSM3
                        }
                        if (groupPreAuthTokenIsOk) {
                            UserGroups.insert {
                                it[this.userId] = requesterUserId
                                it[this.groupId] = groupId
                                it[this.permission] = UserRole.MEMBER
                            }
                            val joinGroupApprovalRows = JoinGroupApprovals.selectAll()
                                .where { (JoinGroupApprovals.requesterWeixinOpenId eq weixinOpenId) and (JoinGroupApprovals.targetGroupId eq groupId) }
                            joinGroupApprovalRows.forEach { joinGroupApprovalRow ->
                                val approvalId = joinGroupApprovalRow[JoinGroupApprovals.approvalId]
                                val approvalRow =
                                    Approvals.selectAll().where { Approvals.approvalId eq approvalId }.firstOrNull()
                                if (approvalRow == null) throw Exception("服务端出现错误")
                                if (approvalRow[Approvals.status] == ApprovalStatus.PENDING) Approvals.deleteWhere {
                                    Approvals.approvalId eq approvalId
                                }
                            }
                        }
                        groupPreAuthTokenIsOk
                    }
                    val textInfo = if (isJoin) "已成功进入团体" else "申请提交成功"
                    call.respond(textInfo)
                }

                // 退出团体
                post("/quit") {
                    val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                        HttpStatusCode.BadRequest, INVALID_GROUP_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    val request = call.receive<GroupQuitRequest>().normalized() as GroupQuitRequest
                    protectedRoute(
                        weixinOpenId,
                        groupId,
                        setOf(ADMIN, MEMBER),
                        CheckType.GROUP_ID,
                        "退出团体",
                        true,
                        request.soterInfo
                    ) {
                        transaction {
                            val userId =
                                weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw BadRequestException(INVALID_JWT)
                            val groupRow = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                                ?: throw BadRequestException(INVALID_GROUP_ID)
                            if (groupRow[Groups.superAdmin] == userId) throw BadRequestException("超级管理员无法退出此团体")
                            UserGroups.deleteWhere {
                                (UserGroups.userId eq userId) and (UserGroups.groupId eq groupId)
                            }
                        }
                        call.respond(HttpStatusCode.OK)
                    }
                }

                // 团体管理员、超管、成员获取团体信息
                get { // getGroupInfo
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    val groupId = call.parameters["groupId"]?.trim() ?: return@get call.respond(
                        HttpStatusCode.BadRequest, INVALID_GROUP_ID
                    )
                    protectedRoute(
                        weixinOpenId,
                        groupId,
                        SUPERADMIN_ADMIN_MEMBER_SET,
                        CheckType.GROUP_ID,
                        "团体管理员、超管、成员获取团体信息",
                        false
                    ) {
                        val groupInfo: GroupInfoResponse = transaction {
                            val groupRow = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                            if (groupRow == null) throw IllegalArgumentException(INVALID_GROUP_ID)
                            val groupName = groupRow[Groups.groupName]
                            val createAt = groupRow[Groups.createdAt]
                            val memberList =
                                UserGroups.selectAll().where { UserGroups.groupId eq groupId }.map { member ->
                                    val userId = member[UserGroups.userId]
                                    val userRow = Users.selectAll().where { Users.userId eq userId }.firstOrNull()
                                    if (userRow == null) throw Exception("服务端出现错误")
                                    val userName = userRow[Users.userName]
                                    val permission = member[UserGroups.permission]
                                    GroupInfoMember(userId, userName, permission)
                                }
                            val isPreAuthTokenEnable =
                                groupRow[Groups.groupPreAuthTokenSM3] != null && groupRow[Groups.preAuthTokenEndTime] != null && groupRow[Groups.preAuthTokenEndTime]!! > LocalDateTime.now()
                            GroupInfoResponse(
                                groupId, groupName, createAt.toKotlinLocalDateTime(), isPreAuthTokenEnable, memberList
                            )
                        }
                        call.respond(groupInfo)
                    }
                }
            }
        }
    }
}

@Serializable
data class JoinedGroupInfo(
    val groupId: String, val groupName: String? = null, val permission: UserRole
)

@Serializable
private data class GroupJoinRequest(
    val requesterUserId: String,
    val requesterUserName: String,
    val requesterComment: String? = null,
    val requesterDevice: String? = null,
    val groupPreAuthToken: String? = null
)

@Serializable
private data class GroupQuitRequest(
    val soterInfo: SoterResultFromUser? = null
)

@OptIn(ExperimentalSerializationApi::class)
@Serializable
private data class GroupInfoResponse(
    val groupId: String,
    val groupName: String? = null,
    val createAt: kotlinx.datetime.LocalDateTime,
    @EncodeDefault val isPreAuthTokenEnable: Boolean = false,
    val memberList: List<GroupInfoMember>? = null
)

@Serializable
data class GroupInfoMember(
    val userId: String, val userName: String? = null, val permission: UserRole
)

fun Transaction.isUserInGroup(userId: String, groupId: String): Boolean {
    val userGroup =
        UserGroups.selectAll().where { (UserGroups.userId eq userId) and (UserGroups.groupId eq groupId) }.firstOrNull()
    return userGroup != null
}

fun Transaction.isGroupCreated(groupId: String): Boolean {
    val group = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
    return group != null
}