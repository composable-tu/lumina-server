package org.linlangwen.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.toKotlinLocalDateTime
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import org.linlangwen.models.*
import org.linlangwen.utils.CheckType
import org.linlangwen.utils.RuntimePermission
import org.linlangwen.utils.WeixinContentSecurityRequest
import org.linlangwen.utils.WeixinContentSecurityScene
import org.linlangwen.utils.protectedRoute
import org.linlangwen.utils.temporaryWeixinContentSecurityCheck
import java.time.LocalDateTime

fun Route.groupRoute(appId: String, appSecret: String) {
    authenticate {
        route("/group/{groupId}") {
            post("/join") {
                val groupId = call.parameters["groupId"] ?: return@post call.respondText(
                    status = HttpStatusCode.BadRequest, text = "无效的团体 ID"
                )
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@post call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val request = call.receive<GroupJoinRequest>()
                val requesterUserId = request.requesterUserId
                val requesterUserName = request.requesterUserName
                val requesterComment = request.requesterComment
                transaction {
                    val userIdFromDB = weixinOpenId2UserIdOrNull(weixinOpenId)
                    if (userIdFromDB != null) {
                        if (userIdFromDB != requesterUserId) throw BadRequestException("您的微信账号似乎曾绑定过用户 ID，但现在您填入的用户 ID 与数据库中您微信绑定的用户 ID 不一致。如需更改用户 ID，请联系客服进行处理。")
                        if (isUserInGroup(userIdFromDB, groupId)) throw BadRequestException("您已加入该团体")
                    }

                    if (!isGroupCreated(groupId)) throw IllegalArgumentException("该团体不存在")

                    // 验证此前是否有同团体号下待审批的申请
                    val joinGroupApproval =
                        JoinGroupApprovals.select((JoinGroupApprovals.requesterWeixinOpenId eq weixinOpenId) and (JoinGroupApprovals.targetGroupId eq groupId))
                            .firstOrNull()
                    if (joinGroupApproval != null) {
                        val approvalId = joinGroupApproval[JoinGroupApprovals.approvalId]
                        val approvalRow = Approvals.select(Approvals.approvalId eq approvalId).firstOrNull()
                        if (approvalRow == null) throw Exception("服务端出现错误")
                        if (approvalRow[Approvals.status] == ApprovalStatus.PENDING) throw BadRequestException("您此前已提交过申请，请等待审批")
                    }
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
                if (!weixinContentSecurityCheck) throw BadRequestException("您提交的内容被微信判定为存在违规内容，请修改后再次提交")
                transaction {
                    val approvalId = Approvals.insert {
                        it[approvalType] = ApprovalTargetType.GROUP_JOIN
                        it[status] = ApprovalStatus.PENDING
                        it[createdAt] = LocalDateTime.now()
                        it[comment] = requesterComment
                    }[Approvals.approvalId]
                    JoinGroupApprovals.insert {
                        it[this.approvalId] = approvalId
                        it[this.targetGroupId] = groupId
                        it[this.requesterUserId] = requesterUserId
                        it[this.requesterUserName] = requesterUserName
                    }
                }
                call.respondText("申请提交成功")
            }
            get { // getGroupInfo
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@get call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val groupId = call.parameters["groupId"] ?: return@get call.respondText(
                    status = HttpStatusCode.BadRequest, text = "无效的团体 ID"
                )
                protectedRoute(weixinOpenId, groupId, setOf(RuntimePermission.ADMIN), CheckType.GROUP_ID, false) {
                    val GroupInfo = transaction {
                        val GroupRow = Groups.select(Groups.groupId eq groupId).firstOrNull()
                        if (GroupRow == null) throw IllegalArgumentException("无效的团体 ID")
                        val GroupName = GroupRow[Groups.groupName]
                        val createAt = GroupRow[Groups.createdAt]
                        val memberList = UserGroups.select(UserGroups.groupId eq groupId).map { member ->
                            val userId = member[UserGroups.userId]
                            val userRow = Users.select(Users.userId eq userId).firstOrNull()
                            if (userRow == null) throw Exception("服务端出现错误")
                            val userName = userRow[Users.userName]
                            val permission = member[UserGroups.permission]
                            GroupInfoMember(userId, userName, permission)
                        }
                        GroupInfoResponse(groupId, GroupName, createAt.toKotlinLocalDateTime(), memberList)
                    }
                    call.respondText(
                        status = HttpStatusCode.OK, text = Json.encodeToString<GroupInfoResponse>(GroupInfo)
                    )
                }
            }
        }
    }
}

@Serializable
data class GroupJoinRequest(
    val requesterUserId: String, val requesterUserName: String, val requesterComment: String? = null
)

@Serializable
data class GroupInfoResponse(
    val groupId: String, val groupName: String? = null, val createAt: kotlinx.datetime.LocalDateTime, val memberList: List<GroupInfoMember>? = null
)

@Serializable
data class GroupInfoMember(
    val userId: String, val userName: String? = null, val permission: UserRole
)

fun Transaction.isUserInGroup(userId: String, groupId: String): Boolean {
    val userGroup = UserGroups.select((UserGroups.userId eq userId) and (UserGroups.groupId eq groupId)).firstOrNull()
    return userGroup != null
}

fun Transaction.isGroupCreated(groupId: String): Boolean {
    val group = Groups.select(Groups.groupId eq groupId).firstOrNull()
    return group != null
}