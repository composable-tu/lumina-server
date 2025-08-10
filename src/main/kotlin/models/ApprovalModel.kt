package org.lumina.models

import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.datetime
import org.lumina.models.ApprovalStatus.*
import org.lumina.models.ApprovalTargetType.*

/**
 * 审批目标类型
 * @property TASK_CREATION 创建任务
 * @property GROUP_JOIN 加入团体
 * @property TASK_EXPAND_GROUP TODO: 扩展任务团体
 */
enum class ApprovalTargetType { TASK_CREATION, GROUP_JOIN, TASK_EXPAND_GROUP }

/**
 * 审批状态
 * @property PENDING 待审批
 * @property APPROVED 已通过
 * @property AUTO_PASSED 自动通过
 * @property REJECTED 已拒绝
 * @property WITHDRAWN 已撤回
 */
enum class ApprovalStatus { PENDING, APPROVED, AUTO_PASSED, REJECTED, WITHDRAWN }

object Approvals : Table("approvals") {
    val approvalId = long("approval_id").autoIncrement().uniqueIndex()  // 审批 ID
    val approvalType = enumerationByName("approval_type", 50, ApprovalTargetType::class)
    val status = enumerationByName("status", 50, ApprovalStatus::class)
    val comment = text("comment").nullable() // 任务请求者的私下评论
    val createdAt = datetime("created_at")
    val reviewedAt = datetime("reviewed_at").nullable()
    val reviewer = reference("reviewer", Users.userId, onDelete = ReferenceOption.NO_ACTION).nullable()

    override val primaryKey = PrimaryKey(approvalId)
}

// 加入团体审批扩展
object JoinGroupApprovals : Table("join_group_approvals") {
    val approvalId = reference("approval_id", Approvals.approvalId, onDelete = ReferenceOption.CASCADE)
    val targetGroupId = reference("target_group_id", Groups.groupId, onDelete = ReferenceOption.CASCADE)
    val requesterUserId = text("requester_user_id")
    val requesterUserName = text("requester_user_name")
    val requesterWeixinOpenId = text("requester_weixin_open_id")
    val preAuthTokenSM3 = text("pre_auth_token_sm3").nullable()
    override val primaryKey = PrimaryKey(approvalId)
}

