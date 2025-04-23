package org.linlangwen.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.receive
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.toKotlinLocalDateTime
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.or
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import org.linlangwen.models.ApprovalStatus
import org.linlangwen.models.ApprovalTargetType
import org.linlangwen.models.Approvals
import org.linlangwen.models.JoinGroupApprovals
import org.linlangwen.models.UserGroups
import org.linlangwen.models.UserRole
import org.linlangwen.models.Users
import org.linlangwen.models.weixinOpenId2UserIdOrNull
import org.linlangwen.utils.CheckType
import org.linlangwen.utils.RuntimePermission
import org.linlangwen.utils.SUPERADMIN_ADMIN_SELF_SET
import org.linlangwen.utils.SUPERADMIN_ADMIN_SET
import org.linlangwen.utils.SoterResultFromUser
import org.linlangwen.utils.protectedRoute

fun Route.approvalRoute() {
    authenticate {
        route("/approvals") {
            get("/{approvalId}") {
                val approvalIdString = call.parameters["approvalId"] ?: return@get call.respondText(
                    status = HttpStatusCode.BadRequest, text = "无效的审批 ID"
                )
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@get call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val approvalId = try {
                    approvalIdString.toLong()
                } catch (_: NumberFormatException) {
                    return@get call.respondText(
                        status = HttpStatusCode.BadRequest, text = "无效的审批 ID"
                    )
                }
                protectedRoute(
                    weixinOpenId, approvalIdString, SUPERADMIN_ADMIN_SELF_SET, CheckType.APPROVAL_ID, false
                ) {
                    val approvalInfo = transaction {
                        val approvalRow = Approvals.select(Approvals.approvalId eq approvalId).firstOrNull()
                            ?: throw IllegalArgumentException("无效的审批 ID")
                        val approvalType = approvalRow[Approvals.approvalType]
                        when (approvalType) {
                            ApprovalTargetType.TASK_CREATION -> {
                                TODO()
                            }

                            ApprovalTargetType.GROUP_JOIN -> {
                                buildJoinGroupApprovalInfo(approvalId, approvalRow)
                            }

                            ApprovalTargetType.TASK_EXPAND_GROUP -> {
                                TODO()
                            }
                        }
                    }
                    call.respondText(
                        status = HttpStatusCode.OK, text = Json.encodeToString<JoinGroupApprovalInfo>(approvalInfo)
                    )
                }
            }

            get("/self") {
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@get call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val approvalInfoList = transaction {
                    // val userId = weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw IllegalArgumentException("无效的 JWT")
                    val approvalInfoList = mutableListOf<ApprovalInfo>()

                    val joinGroupApprovalInfoRows = JoinGroupApprovals.selectAll()
                        .where { JoinGroupApprovals.requesterWeixinOpenId eq weixinOpenId }

                    joinGroupApprovalInfoRows.forEach { joinGroupApprovalInfoRow ->
                        approvalInfoList.add(buildApprovalInfo(joinGroupApprovalInfoRow))
                    }

                    // TODO: taskRequest and taskExpandGroupRequest

                    approvalInfoList.sortedByDescending({ it.createdAt })
                }
                call.respondText(
                    status = HttpStatusCode.OK, text = Json.encodeToString<List<ApprovalInfo>>(approvalInfoList)
                )
            }

            route("/admin") {
                get {
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@get call.respondText(
                            status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                        )
                    val approvalInfoList = transaction {
                        val userId =
                            weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw IllegalArgumentException("无效的 JWT")
                        val managingGroupIdList = UserGroups.selectAll()
                            .where { (UserGroups.userId eq userId) and ((UserGroups.permission eq UserRole.SUPER_ADMIN) or (UserGroups.permission eq UserRole.ADMIN)) }
                            .map { it[UserGroups.groupId] }
                        val approvalInfoList = mutableListOf<ApprovalInfo>()
                        managingGroupIdList.forEach { managingGroupId ->
                            val joinGroupApprovalInfoRows = JoinGroupApprovals.selectAll()
                                .where { JoinGroupApprovals.targetGroupId eq managingGroupId }
                            joinGroupApprovalInfoRows.forEach { joinGroupApprovalInfoRow ->
                                approvalInfoList.add(buildApprovalInfo(joinGroupApprovalInfoRow))
                            }
                        }
                        approvalInfoList.sortedByDescending({ it.createdAt })
                    }
                    call.respondText(
                        status = HttpStatusCode.OK, text = Json.encodeToString<List<ApprovalInfo>>(approvalInfoList)
                    )
                }
                get("/{groupId}") {
                    val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@get call.respondText(
                        status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                    )
                    val groupId = call.parameters["groupId"] ?: return@get call.respondText(
                        status = HttpStatusCode.BadRequest, text = "无效的审批 ID"
                    )
                    protectedRoute(
                        weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, false
                    ){
                        val approvalInfoList = transaction {
                            val approvalInfoList = mutableListOf<ApprovalInfo>()
                            val joinGroupApprovalInfoRows = JoinGroupApprovals.selectAll()
                                .where { JoinGroupApprovals.targetGroupId eq groupId }
                            joinGroupApprovalInfoRows.forEach { joinGroupApprovalInfoRow ->
                                approvalInfoList.add(buildApprovalInfo(joinGroupApprovalInfoRow))
                            }
                            approvalInfoList.sortedByDescending({ it.createdAt })
                        }
                        call.respondText(
                            status = HttpStatusCode.OK, text = Json.encodeToString<List<ApprovalInfo>>(approvalInfoList)
                        )
                    }
                }
            }

            post("/{approvalId}/withdraw") {
                val approvalIdString = call.parameters["approvalId"] ?: return@post call.respondText(
                    status = HttpStatusCode.BadRequest, text = "无效的审批 ID"
                )
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@post call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val approvalId = try {
                    approvalIdString.toLong()
                } catch (_: NumberFormatException) {
                    return@post call.respondText(
                        status = HttpStatusCode.BadRequest, text = "无效的审批 ID"
                    )
                }
                val actionRequest = call.receive<ApprovalActionRequest>()
                val action = requireNotNull(actionRequest.action) { "操作不能为空" }
                if (action != ApprovalAction.WITHDRAW) throw IllegalArgumentException("用户端操作出错")

                protectedRoute(
                    weixinOpenId,
                    approvalIdString,
                    setOf(RuntimePermission.SELF),
                    CheckType.APPROVAL_ID,
                    soter = true,
                    soterResultFromUser = actionRequest.soterInfo
                ) {
                    transaction {
                        val approvalRow = Approvals.select(Approvals.approvalId eq approvalId).firstOrNull()
                            ?: throw IllegalArgumentException("无效的审批 ID")
                        val approvalType = approvalRow[Approvals.approvalType]
                        if (actionRequest.approvalType != approvalType.toString()) throw IllegalArgumentException("用户端传递的审批类型与实际审批类型不匹配")
                        Approvals.update({ Approvals.approvalId eq approvalId }) {
                            it[status] = ApprovalStatus.WITHDRAWN
                        }
                    }
                    call.respondText(
                        status = HttpStatusCode.OK, text = "撤回成功"
                    )
                }
            }

            post("/{approvalId}") {
                val approvalIdString = call.parameters["approvalId"] ?: return@post call.respondText(
                    status = HttpStatusCode.BadRequest, text = "无效的审批 ID"
                )
                val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId") ?: return@post call.respondText(
                    status = HttpStatusCode.Unauthorized, text = "无效的 JWT"
                )
                val approvalId = try {
                    approvalIdString.toLong()
                } catch (_: NumberFormatException) {
                    return@post call.respondText(
                        status = HttpStatusCode.BadRequest, text = "无效的审批 ID"
                    )
                }
                val actionRequest = call.receive<ApprovalActionRequest>()

                protectedRoute(
                    weixinOpenId,
                    approvalIdString,
                    SUPERADMIN_ADMIN_SET,
                    CheckType.APPROVAL_ID,
                    true,
                    actionRequest.soterInfo
                ) {
                    transaction {
                        val approvalRow = Approvals.select(Approvals.approvalId eq approvalId).firstOrNull()
                            ?: throw IllegalArgumentException("无效的审批 ID")
                        val approvalType = approvalRow[Approvals.approvalType]
                        if (actionRequest.approvalType != approvalType.toString()) throw IllegalArgumentException("用户端传递的审批类型与实际审批类型不匹配")
                        when (approvalType) {
                            ApprovalTargetType.TASK_CREATION -> {
                                TODO()
                            }

                            ApprovalTargetType.GROUP_JOIN -> {
                                val joinGroupApprovalRow =
                                    JoinGroupApprovals.select(JoinGroupApprovals.approvalId eq approvalId).firstOrNull()
                                        ?: throw IllegalStateException("服务器错误")
                                when (actionRequest.action) {
                                    ApprovalAction.APPROVE -> {
                                        val targetGroupId = joinGroupApprovalRow[JoinGroupApprovals.targetGroupId]
                                        val requesterUserId = joinGroupApprovalRow[JoinGroupApprovals.requesterUserId]
                                        val requesterUserName =
                                            joinGroupApprovalRow[JoinGroupApprovals.requesterUserName]
                                        val requesterWeixinOpenId =
                                            joinGroupApprovalRow[JoinGroupApprovals.requesterWeixinOpenId]
                                        Users.insert {
                                            it[userId] = requesterUserId
                                            it[Users.weixinOpenId] = requesterWeixinOpenId
                                            it[userName] = requesterUserName
                                        }
                                        UserGroups.insert {
                                            it[userId] = requesterUserId
                                            it[groupId] = targetGroupId
                                            it[permission] = UserRole.MEMBER
                                        }
                                    }

                                    ApprovalAction.REJECT -> {
                                        Approvals.update({ Approvals.approvalId eq approvalId }) {
                                            it[status] = ApprovalStatus.REJECTED
                                        }
                                    }
                                }
                            }

                            ApprovalTargetType.TASK_EXPAND_GROUP -> {
                                TODO()
                            }
                        }
                    }

                }
            }
        }
    }
}

@Serializable
data class ApprovalActionRequest(
    val approvalType: String? = null,
    val action: String? = null,
    val soterInfo: SoterResultFromUser? = null
)

/**
 * 审批操作
 * @property APPROVE 审批通过
 * @property REJECT 审批拒绝
 * @property WITHDRAW 撤回审批
 */
object ApprovalAction {
    const val APPROVE = "approve"
    const val REJECT = "reject"
    const val WITHDRAW = "withdraw"
}

@Serializable
data class ApprovalInfo(
    val approvalId: Long,
    val createdAt: LocalDateTime,
    val approvalType: String,
    val status: String,
    val comment: String?,
    val reviewer: String?,
    val reviewerName: String?,
    val reviewedAt: LocalDateTime?
)

@Serializable
data class JoinGroupApprovalInfo(
    val approvalId: Long,
    val targetGroupId: String,
    val requesterUserId: String,
    val requesterUserName: String,
    val requesterWeixinOpenId: String,
    val createdAt: LocalDateTime,
    val approvalType: String,
    val status: String,
    val comment: String?,
    val reviewer: String?,
    val reviewerName: String?,
    val reviewedAt: LocalDateTime?
)

fun Transaction.buildApprovalInfo(approvalRow: ResultRow): ApprovalInfo {
    val reviewer = approvalRow[Approvals.reviewer]
    val reviewerName =
        if (reviewer == null) null else Users.select(Users.userId eq reviewer).firstOrNull()?.get(Users.userName)
    return ApprovalInfo(
        approvalId = approvalRow[Approvals.approvalId],
        createdAt = approvalRow[Approvals.createdAt].toKotlinLocalDateTime(),
        approvalType = approvalRow[Approvals.approvalType].toString(),
        status = approvalRow[Approvals.status].toString(),
        comment = approvalRow[Approvals.comment],
        reviewer = reviewer,
        reviewerName = reviewerName,
        reviewedAt = approvalRow[Approvals.reviewedAt]?.toKotlinLocalDateTime()
    )
}

fun Transaction.buildJoinGroupApprovalInfo(approvalId: Long, approvalRow: ResultRow): JoinGroupApprovalInfo {
    val joinGroupApprovalRow = JoinGroupApprovals.select(JoinGroupApprovals.approvalId eq approvalId).firstOrNull()
        ?: throw IllegalStateException("服务器错误")
    val reviewer = approvalRow[Approvals.reviewer]
    val reviewerName =
        if (reviewer == null) null else Users.select(Users.userId eq reviewer).firstOrNull()?.get(Users.userName)
    return JoinGroupApprovalInfo(
        approvalId = approvalId,
        targetGroupId = joinGroupApprovalRow[JoinGroupApprovals.targetGroupId],
        requesterUserId = joinGroupApprovalRow[JoinGroupApprovals.requesterUserId],
        requesterUserName = joinGroupApprovalRow[JoinGroupApprovals.requesterUserName],
        requesterWeixinOpenId = joinGroupApprovalRow[JoinGroupApprovals.requesterWeixinOpenId],
        createdAt = approvalRow[Approvals.createdAt].toKotlinLocalDateTime(),
        approvalType = approvalRow[Approvals.approvalType].toString(),
        status = approvalRow[Approvals.status].toString(),
        comment = approvalRow[Approvals.comment],
        reviewer = reviewer,
        reviewerName = reviewerName,
        reviewedAt = approvalRow[Approvals.reviewedAt]?.toKotlinLocalDateTime()
    )
}

