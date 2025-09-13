package org.lumina.models.task

import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.datetime
import org.lumina.models.Users
import org.lumina.models.task.CheckInType.ORDINARY
import org.lumina.models.task.CheckInType.TOKEN
import org.lumina.models.task.InterventionType.*

/**
 * 签到任务类型
 * @property ORDINARY 普通签到
 * @property TOKEN 验证码签到（签到需要输验证码）
 */
enum class CheckInType { ORDINARY, TOKEN }

/**
 * 签到任务信息
 */
object CheckInTaskInfoTable : Table("check_in_task_info_table") {
    val taskId = reference("task_id", Tasks.taskId, onDelete = ReferenceOption.CASCADE)
    val checkInType = enumerationByName("check_in_type", 20, CheckInType::class)
    val checkInTokenSM3 = text("check_in_token_sm3").nullable()
    override val primaryKey = PrimaryKey(taskId)
}

/**
 * 签到任务创建者干预记录类型
 * @property MARK_AS_PARTICIPANT 标记为已参与
 * @property MARK_AS_NOT_PARTICIPANT 标记为未参与
 * @property MARK_AS_PENDING 标记为待定
 */
enum class InterventionType { MARK_AS_PARTICIPANT, MARK_AS_NOT_PARTICIPANT, MARK_AS_PENDING }

/**
 * 签到任务创建者干预记录
 *
 * 新增或修改这里的记录不需要同时修改同用户的签到任务参与记录，因为最终用户任务状态由业务代码比较两处记录后共同决定
 */
object CheckInTaskCreatorInterventionRecord: Table("check_in_task_creator_intervention_record") {
    val taskId = reference("task_id", Tasks.taskId, onDelete = ReferenceOption.CASCADE)
    val userId = reference("user_id", Users.userId, onDelete = ReferenceOption.CASCADE)
    val interventionType = enumerationByName("intervention_type", 30, InterventionType::class)
    val intervenedAt = datetime("intervened_at")
    val intervener = reference("intervener", Users.userId, onDelete = ReferenceOption.SET_NULL)
    override val primaryKey = PrimaryKey(taskId, userId)
}

