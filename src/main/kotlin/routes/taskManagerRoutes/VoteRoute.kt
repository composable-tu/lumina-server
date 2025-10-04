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
package org.lumina.routes.taskManagerRoutes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.toKotlinLocalDateTime
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_TASK_ID
import org.lumina.models.Groups
import org.lumina.models.UserGroups
import org.lumina.models.Users
import org.lumina.models.task.*
import org.lumina.utils.LuminaBadRequestException
import org.lumina.utils.LuminaIllegalStateException
import org.lumina.utils.POIUtil
import org.lumina.utils.sanitizeFilename
import org.lumina.utils.security.CheckType
import org.lumina.utils.security.RuntimePermission
import org.lumina.utils.security.protectedRoute
import kotlinx.datetime.LocalDateTime as KotlinLocalDateTime

fun Route.voteManagerRoute() {
    // 任务创建者获取投票任务参与信息
    get {
        val taskIdString = call.parameters["taskId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, INVALID_TASK_ID
        )
        val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
            HttpStatusCode.Unauthorized, INVALID_JWT
        )
        protectedRoute(
            weixinOpenId,
            taskIdString,
            setOf(RuntimePermission.SELF),
            CheckType.TASK_ID,
            "任务创建者查看投票任务 $taskIdString 参与信息",
            false
        ) {
            val taskId = try {
                taskIdString.toLong()
            } catch (_: NumberFormatException) {
                throw LuminaBadRequestException(INVALID_TASK_ID)
            }
            val voteTaskInfoManagerResponse = transaction {
                getVoteTaskInfoManagerResponse(taskId)
            }
            call.respond(voteTaskInfoManagerResponse)
        }
    }

    // 导出为 Excel
    get("/export") {
        val taskIdString = call.parameters["taskId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, INVALID_TASK_ID
        )
        val weixinOpenId = call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
            HttpStatusCode.Unauthorized, INVALID_JWT
        )
        protectedRoute(
            weixinOpenId,
            taskIdString,
            setOf(RuntimePermission.SELF),
            CheckType.TASK_ID,
            "任务创建者查看投票任务 $taskIdString 参与信息",
            false
        ) {
            val taskId = try {
                taskIdString.toLong()
            } catch (_: NumberFormatException) {
                throw LuminaBadRequestException(INVALID_TASK_ID)
            }
            val voteTaskInfoManagerResponse = transaction {
                getVoteTaskInfoManagerResponse(taskId)
            }
            val excelData = createVoteTaskExcel(voteTaskInfoManagerResponse)
            call.response.header(
                HttpHeaders.ContentDisposition,
                "attachment; filename=\"${voteTaskInfoManagerResponse.taskName.sanitizeFilename()}-投票详情.xlsx\""
            )
            call.respondBytes(excelData, ContentType.Application.Xlsx)
        }
    }
}

private fun Transaction.getVoteTaskInfoManagerResponse(taskId: Long): VoteTaskInfoManagerResponse {
    val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull() ?: throw LuminaBadRequestException(
        INVALID_TASK_ID
    )
    if (taskRow[Tasks.taskType] != TaskType.VOTE) throw LuminaBadRequestException("该任务不是投票任务")

    val voteTaskRow = VoteTaskInfoTable.selectAll().where {
        VoteTaskInfoTable.taskId eq taskId
    }.firstOrNull() ?: throw LuminaBadRequestException("投票任务信息不存在")

    val participationRecords = TaskParticipationRecord.selectAll().where {
        TaskParticipationRecord.taskId eq taskId
    }.toList()

    val taskMemberPolicies = TaskMemberPolicies.selectAll().where {
        TaskMemberPolicies.taskId eq taskId
    }.toList()

    val groupId = taskRow[Tasks.groupId]
    val groupName = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()?.get(
        Groups.groupName
    )
    val creatorId = taskRow[Tasks.creator]
    val creatorName = Users.selectAll().where { Users.userId eq creatorId }.firstOrNull()?.get(
        Users.userName
    )
    val groupMembers = UserGroups.selectAll().where {
        UserGroups.groupId eq groupId
    }.toList()

    val userIds = groupMembers.map { it[UserGroups.userId] }
    val userNameMap = Users.selectAll().where { Users.userId inList userIds }.associateBy { it[Users.userId] }
    val userIdToParticipationRecordMap = participationRecords.associateBy { it[TaskParticipationRecord.userId] }

    val voteOptions = VoteTaskOptionTable.selectAll().where {
        VoteTaskOptionTable.taskId eq taskId
    }.orderBy(VoteTaskOptionTable.sortOrder).toList()

    val voteParticipationRecords = VoteTaskParticipationRecord.selectAll().where {
        VoteTaskParticipationRecord.taskId eq taskId
    }.toList()

    val optionIdToVoteParticipantsMap = mutableMapOf<Long, MutableList<VoteTaskParticipantInfo>>()

    voteParticipationRecords.forEach { record ->
        val optionId = record[VoteTaskParticipationRecord.selectedOption]
        val userId = record[VoteTaskParticipationRecord.userId]
        val userName = userNameMap[userId]?.get(Users.userName)
        val participatedAt =
            userIdToParticipationRecordMap[userId]?.get(TaskParticipationRecord.participatedAt)?.toKotlinLocalDateTime()
                ?: throw LuminaIllegalStateException("服务端错误")

        val participantInfo = VoteTaskParticipantInfo(
            userId = userId, userName = userName, votedAt = participatedAt
        )

        optionIdToVoteParticipantsMap.getOrPut(optionId) { mutableListOf() }.add(participantInfo)
    }

    val voteTaskOptions = voteOptions.map {
        val optionId = it[VoteTaskOptionTable.optionId]
        val participants = optionIdToVoteParticipantsMap[optionId]?.sortedBy { info -> info.votedAt }

        VoteTaskOptionManager(
            optionName = it[VoteTaskOptionTable.optionName],
            sortOrder = it[VoteTaskOptionTable.sortOrder],
            optionDescription = it[VoteTaskOptionTable.optionDescription],
            voteParticipants = participants
        )
    }

    // 获取未参与投票的用户
    val voteNonParticipants = groupMembers.mapNotNull { groupMember ->
        val userId = groupMember[UserGroups.userId]
        val userName = userNameMap[userId]?.get(Users.userName)

        // 判断用户是否在任务参与列表中
        val isUserInTask = when (taskRow[Tasks.memberPolicy]) {
            MemberPolicyType.WHITELIST -> taskMemberPolicies.any { policy ->
                policy[TaskMemberPolicies.userId] == userId
            }

            MemberPolicyType.BLACKLIST -> taskMemberPolicies.none { policy ->
                policy[TaskMemberPolicies.userId] == userId
            }
        }

        // 只有在任务参与列表中且未参与投票的用户才加入未参与者列表
        if (isUserInTask && !userIdToParticipationRecordMap.containsKey(userId)) VoteTaskNonParticipantInfo(
            userId = userId, userName = userName
        ) else null
    }

    return VoteTaskInfoManagerResponse(
        taskId = taskId.toString(),
        groupId = groupId,
        groupName = groupName,
        taskName = taskRow[Tasks.taskName],
        voteMaxSelectable = voteTaskRow[VoteTaskInfoTable.maxSelectable],
        voteCanRecall = voteTaskRow[VoteTaskInfoTable.canRecall],
        isVoteResultPublic = voteTaskRow[VoteTaskInfoTable.isResultPublic],
        voteTaskOptions = voteTaskOptions,
        voteNonParticipants = voteNonParticipants.ifEmpty { null },
        description = taskRow[Tasks.description],
        endTime = taskRow[Tasks.endTime].toKotlinLocalDateTime(),
        createdAt = taskRow[Tasks.createdAt].toKotlinLocalDateTime(),
        creatorId = creatorId,
        creatorName = creatorName
    )
}

private fun createVoteTaskExcel(taskInfo: VoteTaskInfoManagerResponse): ByteArray {
    val taskDetailsSheet = mutableListOf<List<Any?>>()
    taskDetailsSheet.add(listOf("任务基本信息"))
    taskDetailsSheet.add(listOf("任务名称", taskInfo.taskName))
    taskDetailsSheet.add(listOf("任务类型", "投票任务"))
    taskDetailsSheet.add(listOf("最大可选项数", taskInfo.voteMaxSelectable))
    taskDetailsSheet.add(listOf("是否可撤回", taskInfo.voteCanRecall))
    taskDetailsSheet.add(listOf("结果是否公开", taskInfo.isVoteResultPublic))
    taskDetailsSheet.add(listOf("所属团体号", taskInfo.groupId))
    taskDetailsSheet.add(listOf("所属团体名", taskInfo.groupName ?: ""))
    taskDetailsSheet.add(listOf("创建者用户号", taskInfo.creatorId))
    taskDetailsSheet.add(listOf("创建者用户名", taskInfo.creatorName ?: ""))
    taskDetailsSheet.add(listOf("任务描述", taskInfo.description ?: ""))
    taskDetailsSheet.add(listOf("结束时间", taskInfo.endTime))
    taskDetailsSheet.add(listOf("创建时间", taskInfo.createdAt))

    POIUtil.addGeneratedInfo(taskDetailsSheet)

    val optionHeaders = listOf("序号", "选项名称", "选项描述", "投票人数")

    val optionData = taskInfo.voteTaskOptions.mapIndexed { index, option ->
        listOf(index + 1, option.optionName, option.optionDescription ?: "", option.voteParticipants?.size ?: 0)
    }

    val optionsSheet = POIUtil.createSheetDataWithHeaders(optionHeaders, optionData)

    val participantHeaders = listOf("序号", "选项名称", "用户号", "用户名", "投票时间")

    val participantData = mutableListOf<List<Any?>>()
    var participantIndex = 1
    taskInfo.voteTaskOptions.forEach { option ->
        option.voteParticipants?.forEach { participant ->
            participantData.add(
                listOf(
                    participantIndex++,
                    option.optionName,
                    participant.userId,
                    participant.userName ?: "",
                    participant.votedAt
                )
            )
        }
    }

    val participantsSheet = if (participantData.isNotEmpty()) {
        POIUtil.createSheetDataWithHeaders(participantHeaders, participantData)
    } else listOf(participantHeaders)

    val nonParticipantHeaders = listOf("序号", "未参与用户号", "未参与用户名")

    val nonParticipantData = taskInfo.voteNonParticipants?.mapIndexed { index, nonParticipant ->
        listOf(
            index + 1, nonParticipant.userId, nonParticipant.userName ?: ""
        )
    } ?: emptyList()

    val nonParticipantsSheet = if (nonParticipantData.isNotEmpty()) {
        POIUtil.createSheetDataWithHeaders(nonParticipantHeaders, nonParticipantData)
    } else listOf(nonParticipantHeaders)

    val sheets =
        mutableMapOf("任务详情" to taskDetailsSheet, "投票选项" to optionsSheet, "投票详情" to participantsSheet)

    if (taskInfo.voteNonParticipants?.isNotEmpty() == true) sheets["未参与者"] = nonParticipantsSheet

    return POIUtil.createExcel(sheets)
}

@Serializable
private data class VoteTaskInfoManagerResponse(
    val taskId: String,
    val groupId: String,
    val groupName: String? = null,
    val taskName: String,
    val voteMaxSelectable: Int,
    val voteCanRecall: Boolean,
    val isVoteResultPublic: Boolean,
    val voteTaskOptions: List<VoteTaskOptionManager>,
    val voteNonParticipants: List<VoteTaskNonParticipantInfo>? = null,
    val description: String? = null,
    val endTime: KotlinLocalDateTime,
    val createdAt: KotlinLocalDateTime,
    val creatorId: String,
    val creatorName: String? = null,
)

@Serializable
private data class VoteTaskOptionManager(
    val optionName: String,
    val sortOrder: Int,
    val optionDescription: String? = null,
    val voteParticipants: List<VoteTaskParticipantInfo>? = null
)

@Serializable
private data class VoteTaskParticipantInfo(
    val userId: String, val userName: String? = null, val votedAt: KotlinLocalDateTime
)

@Serializable
private data class VoteTaskNonParticipantInfo(val userId: String, val userName: String? = null)
