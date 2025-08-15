package org.lumina.models

import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.datetime
import org.lumina.models.CheckInType.ORDINARY
import org.lumina.models.CheckInType.TOKEN
import org.lumina.models.MemberPolicyType.BLACKLIST
import org.lumina.models.MemberPolicyType.WHITELIST
import org.lumina.models.TaskType.*

/**
 * 任务类型枚举
 * @property CHECK_IN 签到任务
 * @property LOTTERY 抽签/抽奖任务
 * @property VOTE 投票任务
 */
enum class TaskType { CHECK_IN, LOTTERY, VOTE }

/**
 * 成员策略类型
 * @property WHITELIST 白名单模式（只有选中成员可参加，新成员默认不可参加）
 * @property BLACKLIST 黑名单模式（选中成员不可参加，其余成员可参加，包括新成员）
 */
enum class MemberPolicyType { WHITELIST, BLACKLIST }

/**
 * 任务表
 */
object Tasks : Table("tasks") {
    val taskId = long("task_id").autoIncrement().uniqueIndex()
    val groupId = reference("group_id", Groups.groupId, onDelete = ReferenceOption.CASCADE)
    val taskName = text("task_name")
    val taskType = enumerationByName("task_type", 20, TaskType::class)
    val description = text("description").nullable()
    val endTime = datetime("end_time")
    val memberPolicy = enumerationByName("member_policy", 20, MemberPolicyType::class)
    val createdAt = datetime("created_at")
    val creator = reference("creator", Users.userId, onDelete = ReferenceOption.CASCADE)

    override val primaryKey = PrimaryKey(taskId)
}

/**
 * 任务成员策略表（用于黑白名单）
 */
object TaskMemberPolicies : Table("task_member_policies") {
    val taskId = reference("task_id", Tasks.taskId, onDelete = ReferenceOption.CASCADE)
    val userId = reference("user_id", Users.userId, onDelete = ReferenceOption.CASCADE)

    override val primaryKey = PrimaryKey(taskId, userId)
}

/**
 * 任务参与记录
 */
object TaskParticipationRecord: Table("task_participation_record") {
    val taskId = reference("task_id", Tasks.taskId, onDelete = ReferenceOption.CASCADE)
    val userId = reference("user_id", Users.userId, onDelete = ReferenceOption.CASCADE)
    val participatedAt = datetime("participated_at")
    override val primaryKey = PrimaryKey(taskId, userId)
}

/**
 * 签到任务类型
 * @property ORDINARY 普通签到
 * @property TOKEN 验证码签到（签到需要输验证码）
 */
enum class CheckInType { ORDINARY, TOKEN }

object CheckInTaskInfoTable : Table("check_in_task_info_table") {
    val taskId = reference("task_id", Tasks.taskId, onDelete = ReferenceOption.CASCADE)
    val checkInType = enumerationByName("check_in_type", 20, CheckInType::class)
    val checkInTokenSM3 = text("check_in_token_sm3").nullable()
    override val primaryKey = PrimaryKey(taskId)
}


