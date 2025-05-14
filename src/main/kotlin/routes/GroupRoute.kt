package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.*
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
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_GROUP_ID
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.models.*
import org.lumina.utils.*
import java.security.MessageDigest
import java.time.LocalDateTime

/**
 * 团体路由
 *
 * 功能：
 * - 申请加入团体
 * - 获取团体基础信息
 */
fun Route.groupRoute(appId: String, appSecret: String) {
    authenticate {
        route("/group/{groupId}") {
            post("/join") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val request = call.receive<GroupJoinRequest>().normalized() as GroupJoinRequest
                val requesterUserId = request.requesterUserId
                val requesterUserName = request.requesterUserName
                val requesterComment = request.requesterComment
                val entryPassword = request.entryPassword
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
                val isJoin = transaction {
                    // 这里的判断逻辑是，如果进团体临时令牌没写就认为是应该经过审批加入请求，进入审批数据库
                    // 如果进团体临时令牌不符合数据库设置则直接打回，请求不进入数据库
                    // 如果临时令牌正确则直接进团体
                    val messageDigest = MessageDigest.getInstance("SM3")
                    val entryPasswordSM3 = if (entryPassword.isNullOrEmpty()) null else messageDigest.digest(entryPassword.toByteArray()).toHashString()
                    val groupEntryPasswordIsOk = if (entryPassword.isNullOrEmpty()) false else {
                        val groupRow = Groups.select(Groups.groupId eq groupId).firstOrNull()
                        if (groupRow == null) throw Exception("服务端出现错误")
                        val groupEntryPasswordSM3 = groupRow[Groups.entryPasswordSM3]
                        if (entryPasswordSM3 != groupEntryPasswordSM3) {
                            throw BadRequestException("临时令牌错误")
                        } else {
                            val groupPasswordEndTime = groupRow[Groups.passwordEndTime]
                            groupPasswordEndTime != null && groupPasswordEndTime >= LocalDateTime.now()
                        }
                    }
                    val approvalId = Approvals.insert {
                        it[approvalType] = ApprovalTargetType.GROUP_JOIN
                        it[status] = if (groupEntryPasswordIsOk) ApprovalStatus.AUTO_PASSED else ApprovalStatus.PENDING
                        it[createdAt] = LocalDateTime.now()
                        it[comment] = requesterComment
                    }[Approvals.approvalId]
                    JoinGroupApprovals.insert {
                        it[this.approvalId] = approvalId
                        it[this.targetGroupId] = groupId
                        it[this.requesterUserId] = requesterUserId
                        it[this.requesterUserName] = requesterUserName
                        it[this.requesterWeixinOpenId] = weixinOpenId
                        if (!entryPassword.isNullOrEmpty()) it[this.entryPasswordSM3] = entryPasswordSM3
                    }
                    if (groupEntryPasswordIsOk) {
                        UserGroups.insert {
                            it[this.userId] = requesterUserId
                            it[this.groupId] = groupId
                            it[this.permission] = UserRole.MEMBER
                        }
                    }
                    groupEntryPasswordIsOk
                }
                val textInfo = if (isJoin) "已成功进入团体" else "申请提交成功"
                call.respond(textInfo)
            }
            get { // getGroupInfo
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val groupId = call.parameters["groupId"]?.trim() ?: return@get call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
                )
                protectedRoute(weixinOpenId, groupId, setOf(RuntimePermission.ADMIN), CheckType.GROUP_ID, false) {
                    val groupInfo = transaction {
                        val groupRow = Groups.select(Groups.groupId eq groupId).firstOrNull()
                        if (groupRow == null) throw IllegalArgumentException(INVALID_GROUP_ID)
                        val groupName = groupRow[Groups.groupName]
                        val createAt = groupRow[Groups.createdAt]
                        val memberList = UserGroups.select(UserGroups.groupId eq groupId).map { member ->
                            val userId = member[UserGroups.userId]
                            val userRow = Users.select(Users.userId eq userId).firstOrNull()
                            if (userRow == null) throw Exception("服务端出现错误")
                            val userName = userRow[Users.userName]
                            val permission = member[UserGroups.permission]
                            GroupInfoMember(userId, userName, permission)
                        }
                        GroupInfoResponse(groupId, groupName, createAt.toKotlinLocalDateTime(), memberList = memberList)
                    }
                    call.respond(HttpStatusCode.OK, Json.encodeToString<GroupInfoResponse>(groupInfo))
                }
            }
        }
    }
}

@Serializable
data class GroupJoinRequest(
    val requesterUserId: String,
    val requesterUserName: String,
    val requesterComment: String? = null,
    val entryPassword: String? = null
)

@Serializable
data class GroupInfoResponse(
    val groupId: String,
    val groupName: String? = null,
    val createAt: kotlinx.datetime.LocalDateTime,
    val isPasswordEnable: Boolean = false,
    val memberList: List<GroupInfoMember>? = null
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