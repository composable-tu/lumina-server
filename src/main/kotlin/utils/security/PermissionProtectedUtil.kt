package org.lumina.utils.security

import io.ktor.server.routing.*
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.experimental.newSuspendedTransaction
import org.lumina.models.*
import org.lumina.utils.getUserIdByWeixinOpenIdOrNullFromDB
import org.lumina.utils.security.CheckType.*
import org.lumina.utils.security.RuntimePermission.*
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/**
 * 运行时角色权限
 *
 * 注意：权限检查采用精确匹配机制，仅当用户角色与指定权限完全匹配时才允许访问。
 *
 * 例：如果指定了权限为只有成员，则超管和管理员不可访问；如果指定了权限为只有管理员，则超管和成员不可访问
 * @property SUPER_ADMIN 超级管理员（唯一，可转让）
 * @property ADMIN 管理员
 * @property MEMBER 普通成员
 * @property SELF 自身
 */
enum class RuntimePermission { SUPER_ADMIN, ADMIN, MEMBER, SELF }

/**
 * 运行时权限集：超级管理员、管理员、自身
 */
val SUPERADMIN_ADMIN_SELF_SET = setOf(SUPER_ADMIN, ADMIN, SELF)

/**
 * 运行时权限集：超级管理员、管理员
 */
val SUPERADMIN_ADMIN_SET = setOf(SUPER_ADMIN, ADMIN)

/**
 * 运行时权限集：超级管理员、自身
 */
val SUPERADMIN_SELF_SET = setOf(SUPER_ADMIN, SELF)

/**
 * 运行时权限集：超级管理员、管理员、成员
 */
val SUPERADMIN_ADMIN_MEMBER_SET = setOf(SUPER_ADMIN, ADMIN, MEMBER)

/**
 * 检查类型
 *
 * @property TASK_ID 基于任务 ID 的检查
 * @property GROUP_ID 基于用户组 ID 的检查
 * @property APPROVAL_ID 基于审批 ID 的检查
 */
enum class CheckType { TASK_ID, GROUP_ID, APPROVAL_ID }

/**
 * 路由保护，用于检查用户是否有权执行某个操作
 * @param checkType ID 检查类型
 * @param challenge 为此次鉴权准备的识别信息字符串，供调用者识别本次请求。例如：如果场景为请求用户对某操作进行授权确认，则可以将该操作名填入此参数。
 * @param soter 启用后，无论角色权限如何，如果该用户设置了启用 SOTER 生物认证，则需要验证 SOTER 才能执行该操作
 */
suspend fun Route.protectedRoute(
    weixinOpenId: String,
    groupIdOrTaskIdOrApproveId: String,
    permissions: Set<RuntimePermission>,
    checkType: CheckType,
    challenge: String,
    soter: Boolean,
    soterResultFromUser: SoterResultFromUser? = null,
    action: suspend () -> Unit
) {
    if (permissions.isEmpty()) throw IllegalArgumentException("权限不能为空")
    val appId = environment.config.property("wx.appId").getString()
    val appSecret = environment.config.property("wx.appSecret").getString()
    var errorText: String? = null
    fun setError(text: String): Boolean {
        errorText = text
        return false
    }

    val canAction: Boolean = newSuspendedTransaction {
        val userId =
            getUserIdByWeixinOpenIdOrNullFromDB(weixinOpenId) ?: return@newSuspendedTransaction setError("用户未注册")

        if (soter) {
            // 检查用户是否设置了 SOTER 生物认证
            val isSoterEnabled = isUserSoterEnabledWithUserId(userId)
            if (isSoterEnabled) {
                if (soterResultFromUser == null) return@newSuspendedTransaction setError("SOTER 验证失败")
                if (soterResultFromUser.json_string.isEmpty() || soterResultFromUser.json_signature.isEmpty()) return@newSuspendedTransaction setError(
                    "SOTER 验证参数缺失"
                )
                val weixinSoterCheck = weixinSoterCheck(
                    appId, appSecret, WeixinSoterCheckRequest(
                        weixinOpenId, soterResultFromUser.json_string, soterResultFromUser.json_signature
                    )
                )
                if (!weixinSoterCheck) return@newSuspendedTransaction setError("SOTER 验证失败")
            }
        }
        return@newSuspendedTransaction when (checkType) {
            GROUP_ID -> {
                val isVerificationPassed = protectedRouteWithGroupId(userId, groupIdOrTaskIdOrApproveId, permissions)
                if (!isVerificationPassed) setError("您没有操作此行动的权限") else true
            }

            TASK_ID -> {
                val taskId = try {
                    groupIdOrTaskIdOrApproveId.toLong()
                } catch (_: NumberFormatException) {
                    return@newSuspendedTransaction setError("无效的审批 ID")
                }
                val isVerificationPassed = protectedRouteWithTaskId(userId, taskId, permissions)
                if (!isVerificationPassed) setError("您没有操作此行动的权限") else true
            }

            APPROVAL_ID -> {
                val approveId = try {
                    groupIdOrTaskIdOrApproveId.toLong()
                } catch (_: NumberFormatException) {
                    return@newSuspendedTransaction setError("无效的审批 ID")
                }
                val isVerificationPassed = protectedRouteWithApproveId(weixinOpenId, userId, approveId, permissions)
                if (!isVerificationPassed) setError("您没有操作此行动的权限") else true
            }
        }
    }
    if (canAction) {
        val time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
        println("$time 用户 $weixinOpenId 向 $checkType $groupIdOrTaskIdOrApproveId 执行 $challenge")
        action()
    } else throw IllegalArgumentException(errorText)
}

/**
 * 基于 User ID 和 Group ID 检查用户是否有权对某团体执行某个操作
 */
fun Transaction.protectedRouteWithGroupId(
    userId: String, groupId: String, permissions: Set<RuntimePermission>
): Boolean {
    // 获取用户在指定团体中的权限
    val userGroup = UserGroups.selectAll().where {
        (UserGroups.userId eq userId) and (UserGroups.groupId eq groupId)
    }.firstOrNull() ?: return false
    val userPermission = userGroup[UserGroups.permission]


    // 检查用户权限是否满足要求
    return when (userPermission) {
        UserRole.SUPER_ADMIN -> permissions.contains(SUPER_ADMIN)
        UserRole.ADMIN -> permissions.contains(ADMIN)
        UserRole.MEMBER -> permissions.contains(MEMBER)
    }
}

/**
 * 基于 User ID 和 Task ID 检查用户是否有权对某任务执行某个操作
 */
fun Transaction.protectedRouteWithTaskId(
    userId: String, taskId: Long, permissions: Set<RuntimePermission>
): Boolean {
    val taskRow =
        Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull() ?: throw IllegalArgumentException("任务不存在")
    val creator = taskRow[Tasks.creator]
    if (creator == userId && permissions.contains(SELF)) return true else return protectedRouteWithGroupId(
        userId, taskRow[Tasks.groupId], permissions
    )
}

/**
 * 基于 User ID 和 Approve ID 检查用户是否有权对某审批执行某个操作
 */
fun Transaction.protectedRouteWithApproveId(
    weixinOpenId: String, userId: String, approveId: Long, permissions: Set<RuntimePermission>
): Boolean {
    val approveRow = Approvals.selectAll().where { Approvals.approvalId eq approveId }.firstOrNull()
        ?: throw IllegalArgumentException("审批不存在")
    return when (approveRow[Approvals.approvalType]) {
        ApprovalTargetType.GROUP_JOIN -> {
            val joinGroupApprovalRow =
                JoinGroupApprovals.selectAll().where { JoinGroupApprovals.approvalId eq approveId }.firstOrNull()
                    ?: throw IllegalArgumentException("审批不存在")
            val requesterWeixinOpenId = joinGroupApprovalRow[JoinGroupApprovals.requesterWeixinOpenId]
            val targetGroupId = joinGroupApprovalRow[JoinGroupApprovals.targetGroupId]
            if (permissions.contains(SELF)) requesterWeixinOpenId == weixinOpenId || protectedRouteWithGroupId(
                userId, targetGroupId, permissions
            ) else protectedRouteWithGroupId(userId, targetGroupId, permissions)
        }

        ApprovalTargetType.TASK_CREATION -> {
            // TODO: 任务创建申请
            true
        }
    }
}

/**
 * 在数据库中查询用户是否启用重要操作需经过腾讯 SOTER 生物认证保护
 */
fun Transaction.isUserSoterEnabledWithUserId(userId: String): Boolean {
    return Users.selectAll().where { Users.userId eq userId }.firstOrNull()?.get(Users.isSoterEnabled)
        ?: throw IllegalArgumentException("服务器错误")
}

