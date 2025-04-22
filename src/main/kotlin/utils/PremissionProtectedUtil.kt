package org.linlangwen.utils

import io.ktor.server.routing.*
import kotlinx.coroutines.runBlocking
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.linlangwen.models.*
import org.linlangwen.utils.CheckType.*
import org.linlangwen.utils.RuntimePermission.*

/**
 * 运行时角色权限
 * @property SUPER_ADMIN 超级管理员（唯一，可转让）
 * @property ADMIN 管理员
 * @property MEMBER 普通成员
 * @property SELF 自身
 */
enum class RuntimePermission { SUPER_ADMIN, ADMIN, MEMBER, SELF }

/**
 * 运行时权限集：超级管理员、管理员、自身
 */
val SUPERADMIN_ADMIN_SELF_SET =  setOf(SUPER_ADMIN, ADMIN, SELF)

/**
 * 运行时权限集：超级管理员、管理员
 */
val SUPERADMIN_ADMIN_SET =  setOf(SUPER_ADMIN, ADMIN)

/**
 * 运行时权限集：超级管理员、自身
 */
val SUPERADMIN_SELF_SET =  setOf(SUPER_ADMIN, SELF)

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
 * @param soter 启用后，无论角色权限如何，如果该用户设置了启用 SOTER 生物认证，则需要验证 SOTER 才能执行该操作
 */
suspend fun Route.protectedRoute(
    weixinOpenId: String,
    groupIdOrTaskIdOrApproveId: String,
    permissions: Set<RuntimePermission>,
    checkType: CheckType,
    soter: Boolean,
    soterResultFromUser: SoterResultFromUser? = null,
    action: suspend () -> Unit
) {
    if (permissions.isEmpty()) throw IllegalArgumentException("权限不能为空")
    val appId = environment.config.property("appId").getString()
    val appSecret = environment.config.property("appSecret").getString()
    var errorText: String? = null
    fun setError(text: String): Boolean {
        errorText = text
        return false
    }

    val canAction: Boolean = transaction {
        val userId = getUserIdByWeixinOpenIdOrNullFromDB(weixinOpenId)
        if (userId == null) return@transaction setError("用户未注册")

        if (soter) {
            // 检查用户是否设置了 SOTER 生物认证
            val isSoterEnabled = isUserSoterEnabledWithUserId(userId)
            if (isSoterEnabled) {
                if (soterResultFromUser == null) return@transaction setError("SOTER 验证失败")
                if (soterResultFromUser.json_string.isNullOrEmpty() || soterResultFromUser.json_signature.isNullOrEmpty()) return@transaction setError("SOTER 验证参数缺失")
                val weixinSoterCheck = runBlocking {
                    weixinSoterCheck(
                        appId,
                        appSecret,
                        WeixinSoterCheckRequest(weixinOpenId, soterResultFromUser.json_string, soterResultFromUser.json_signature)
                    )
                }
                if (!weixinSoterCheck) return@transaction setError("SOTER 验证失败")
            }
        }
        return@transaction when (checkType) {
            GROUP_ID -> {
                val isVerificationPassed = protectedRouteWithGroupId(userId, groupIdOrTaskIdOrApproveId, permissions)
                if (!isVerificationPassed) setError("您没有操作此行动的权限") else true
            }

            TASK_ID -> {
                // val isVerificationPassed = protectedRouteWithTaskId(userId, groupIdOrTaskIdOrApproveId, permissions)
                // if (!isVerificationPassed) setError("无权限") // 无权限
                // else true
                true
            }

            APPROVAL_ID -> {
                val approveId = try {
                    groupIdOrTaskIdOrApproveId.toLong()
                } catch (e: NumberFormatException) {
                    return@transaction setError("无效的审批 ID")
                }
                val isVerificationPassed =
                    protectedRouteWithApproveId(weixinOpenId, userId, approveId, permissions)
                if (!isVerificationPassed) setError("无权限") else true
            }
        }
    }
    if (canAction) action() else throw IllegalArgumentException(errorText)
}

fun Transaction.protectedRouteWithGroupId(
    userId: String, groupId: String, permissions: Set<RuntimePermission>
): Boolean {
    // 获取用户在指定团体中的权限
    val userGroup = UserGroups.selectAll().where {
        (UserGroups.userId eq userId) and (UserGroups.groupId eq groupId)
    }.firstOrNull() ?:return false
    val userPermission = userGroup[UserGroups.permission]


    // 检查用户权限是否满足要求
    return when (userPermission) {
        UserRole.SUPER_ADMIN -> permissions.contains(SUPER_ADMIN)
        UserRole.ADMIN -> permissions.contains(ADMIN)
        UserRole.MEMBER -> permissions.contains(MEMBER)
    }
}

fun Transaction.protectedRouteWithTaskId(
    userId: String, taskId: String, permissions: Set<RuntimePermission>
): Boolean {
    return TODO()
}

fun Transaction.protectedRouteWithApproveId(
    weixinOpenId: String, userId: String, approveId: Long, permissions: Set<RuntimePermission>
): Boolean {
    val approveRow = Approvals.select(Approvals.approvalId eq approveId).firstOrNull() ?: throw IllegalArgumentException("审批不存在")
    return when (approveRow[Approvals.approvalType]) {
        ApprovalTargetType.GROUP_JOIN -> {
            val joinGroupApprovalRow = JoinGroupApprovals.select(JoinGroupApprovals.approvalId eq approveId).firstOrNull() ?: throw IllegalArgumentException("审批不存在")
            val requesterWeixinOpenId = joinGroupApprovalRow[JoinGroupApprovals.requesterWeixinOpenId]
            val targetGroupId = joinGroupApprovalRow[JoinGroupApprovals.targetGroupId]
            if (permissions.contains(SELF)) requesterWeixinOpenId == weixinOpenId else protectedRouteWithGroupId(
                userId, targetGroupId, permissions
            )
        }

        ApprovalTargetType.TASK_CREATION -> {
            // TODO: 任务创建申请
            true
        }
        ApprovalTargetType.TASK_EXPAND_GROUP -> {
            // TODO:
            true
        }
    }
}

fun Transaction.isUserSoterEnabledWithUserId(userId: String): Boolean {
    return Users.select(Users.userId eq userId).firstOrNull()?.get(Users.isSoterEnabled)
        ?: throw IllegalArgumentException("服务器错误")
}

