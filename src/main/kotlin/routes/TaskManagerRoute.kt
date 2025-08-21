package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.toKotlinLocalDateTime
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.jdbc.update
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_TASK_ID
import org.lumina.models.Groups
import org.lumina.models.UserGroups
import org.lumina.models.Users
import org.lumina.models.task.*
import org.lumina.models.task.InterventionType.MARK_AS_PARTICIPANT
import org.lumina.models.weixinOpenId2UserIdOrNull
import org.lumina.utils.LuminaBadRequestException
import org.lumina.utils.normalized
import org.lumina.utils.security.*
import java.time.LocalDateTime
import kotlinx.datetime.LocalDateTime as KotlinLocalDateTime

fun Route.taskManagerRoute(appId: String, appSecret: String) {
    authenticate {
        route("/taskManager") {

            route("/checkIn/{taskId}") {

                // 任务创建者获取对于创建者的签到任务信息
                get {
                    val taskIdString = call.parameters["taskId"] ?: return@get call.respond(
                        HttpStatusCode.BadRequest, INVALID_TASK_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    protectedRoute(
                        weixinOpenId,
                        taskIdString,
                        setOf(RuntimePermission.SELF),
                        CheckType.TASK_ID,
                        "任务创建者查看任务 $taskIdString",
                        false
                    ) {
                        val taskId = try {
                            taskIdString.toLong()
                        } catch (_: NumberFormatException) {
                            throw LuminaBadRequestException(INVALID_TASK_ID)
                        }
                        val checkInTaskInfoManagerResponse = transaction {
                            val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull()
                                ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            if (taskRow[Tasks.taskType] != TaskType.CHECK_IN) throw LuminaBadRequestException("该任务不是签到任务")
                            val checkInTaskRow = CheckInTaskInfoTable.selectAll().where {
                                CheckInTaskInfoTable.taskId eq taskId
                            }.firstOrNull() ?: throw LuminaBadRequestException("签到任务信息不存在")

                            val participationRecords = TaskParticipationRecord.selectAll().where {
                                TaskParticipationRecord.taskId eq taskId
                            }.toList()
                            val interventionRecords = CheckInTaskCreatorInterventionRecord.selectAll().where {
                                CheckInTaskCreatorInterventionRecord.taskId eq taskId
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

                            val userNameMap = Users.selectAll().toList().associateBy { it[Users.userId] }
                            val userIdToParticipationRecordMap =
                                participationRecords.associateBy { it[TaskParticipationRecord.userId] }
                            val userIdToInterventionRecordMap =
                                interventionRecords.associateBy { it[CheckInTaskCreatorInterventionRecord.userId] }


                            val memberList = groupMembers.map { groupMember ->
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

                                val status = if (!isUserInTask) TaskStatus.NOT_REQUIRED else {
                                    val interventionRecord = userIdToInterventionRecordMap[userId]
                                    val participationRecord = userIdToParticipationRecordMap[userId]
                                    val isExpired = taskRow[Tasks.endTime].isBefore(LocalDateTime.now())
                                    when (interventionRecord?.get(CheckInTaskCreatorInterventionRecord.interventionType)) {
                                        InterventionType.MARK_AS_NOT_PARTICIPANT -> TaskStatus.MARK_AS_NOT_PARTICIPANT
                                        InterventionType.MARK_AS_PENDING -> TaskStatus.MARK_AS_PENDING
                                        MARK_AS_PARTICIPANT -> if (participationRecord == null) TaskStatus.MARK_AS_PARTICIPANT else TaskStatus.PARTICIPATED

                                        null -> if (participationRecord == null) {
                                            if (isExpired) TaskStatus.EXPIRED else TaskStatus.PENDING
                                        } else TaskStatus.PARTICIPATED
                                    }
                                }

                                val participatedAt =
                                    userIdToParticipationRecordMap[userId]?.get(TaskParticipationRecord.participatedAt)
                                        ?.toKotlinLocalDateTime()

                                CheckInTaskUserStatusInfo(
                                    userId = userId,
                                    userName = userName,
                                    status = status,
                                    participatedAt = participatedAt
                                )
                            }

                            CheckInTaskInfoManagerResponse(
                                taskId = taskIdString,
                                groupId = groupId,
                                groupName = groupName,
                                taskName = taskRow[Tasks.taskName],
                                checkInType = checkInTaskRow[CheckInTaskInfoTable.checkInType],
                                description = taskRow[Tasks.description],
                                endTime = taskRow[Tasks.endTime].toKotlinLocalDateTime(),
                                createdAt = taskRow[Tasks.createdAt].toKotlinLocalDateTime(),
                                creatorId = creatorId,
                                creatorName = creatorName,
                                memberList = memberList
                            )
                        }
                        call.respond(checkInTaskInfoManagerResponse)
                    }
                }

                // 任务创建者干预用户签到记录
                post("/interveneUser") {
                    val taskIdString = call.parameters["taskId"] ?: return@post call.respond(
                        HttpStatusCode.BadRequest, INVALID_TASK_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )

                    val encryptRequest = call.receive<EncryptContentRequest>()
                    val weixinUserCryptoKeyRequest = WeixinUserCryptoKeyRequest(
                        weixinOpenId,
                        encryptRequest.encryptContent,
                        encryptRequest.encryptVersion,
                        encryptRequest.hmacSignature,
                        encryptRequest.weixinLoginCode
                    )

                    val request = Json.decodeFromString<InterveneUserCheckInRequest>(
                        weixinDecryptContent(appId, appSecret, weixinUserCryptoKeyRequest)
                    ).normalized()

                    protectedRoute(
                        weixinOpenId,
                        taskIdString,
                        setOf(RuntimePermission.SELF),
                        CheckType.TASK_ID,
                        "任务创建者干预任务 $taskIdString 签到记录",
                        true,
                        request.soterInfo
                    ) {
                        val taskId = try {
                            taskIdString.toLong()
                        } catch (_: NumberFormatException) {
                            throw LuminaBadRequestException(INVALID_TASK_ID)
                        }
                        transaction {
                            val userId =
                                weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw LuminaBadRequestException(INVALID_JWT)
                            val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull()
                                ?: throw LuminaBadRequestException(INVALID_TASK_ID)

                            val targetUserId = request.userId
                            val interventionType = request.interventionType

                            val taskMemberPolicies = TaskMemberPolicies.selectAll().where {
                                TaskMemberPolicies.taskId eq taskId
                            }.toList()

                            val isUserInTask = when (taskRow[Tasks.memberPolicy]) {
                                MemberPolicyType.WHITELIST -> taskMemberPolicies.any { policy ->
                                    policy[TaskMemberPolicies.userId] == targetUserId
                                }

                                MemberPolicyType.BLACKLIST -> taskMemberPolicies.none { policy ->
                                    policy[TaskMemberPolicies.userId] == targetUserId
                                }
                            }
                            if (!isUserInTask) throw LuminaBadRequestException("目标用户不在任务参与列表中")

                            val interventionRecord = CheckInTaskCreatorInterventionRecord.selectAll().where {
                                (CheckInTaskCreatorInterventionRecord.taskId eq taskId) and (CheckInTaskCreatorInterventionRecord.userId eq targetUserId)
                            }.firstOrNull()

                            if (interventionType == MARK_AS_PARTICIPANT && interventionRecord == null) {
                                val taskParticipationRecord = TaskParticipationRecord.selectAll().where {
                                    (TaskParticipationRecord.taskId eq taskId) and (TaskParticipationRecord.userId eq targetUserId)
                                }.firstOrNull()
                                if (taskParticipationRecord != null) throw LuminaBadRequestException(
                                    "目标用户已参与任务，因此无需再次标记为参与者"
                                )
                            }

                            if (interventionRecord != null) {
                                if (interventionRecord[CheckInTaskCreatorInterventionRecord.interventionType] == interventionType) throw LuminaBadRequestException(
                                    "目标用户已被干预为该状态，因此无需再次干预"
                                ) else CheckInTaskCreatorInterventionRecord.update({
                                    (CheckInTaskCreatorInterventionRecord.taskId eq taskId) and (CheckInTaskCreatorInterventionRecord.userId eq targetUserId)
                                }) {
                                    it[this.interventionType] = interventionType
                                    it[this.intervenedAt] = LocalDateTime.now()
                                    it[this.intervener] = userId
                                }
                            } else CheckInTaskCreatorInterventionRecord.insert {
                                it[this.taskId] = taskId
                                it[this.userId] = targetUserId
                                it[this.interventionType] = interventionType
                                it[this.intervenedAt] = LocalDateTime.now()
                                it[this.intervener] = userId
                            }
                        }
                        call.respond(HttpStatusCode.OK)
                    }
                }
            }
        }
    }
}

@Serializable
private data class CheckInTaskInfoManagerResponse(
    val taskId: String,
    val groupId: String,
    val groupName: String? = null,
    val taskName: String,
    val checkInType: CheckInType,
    val description: String? = null,
    val endTime: KotlinLocalDateTime,
    val createdAt: KotlinLocalDateTime,
    val creatorId: String,
    val creatorName: String? = null,
    val memberList: List<CheckInTaskUserStatusInfo>
)

@Serializable
private data class CheckInTaskUserStatusInfo(
    val userId: String,
    val userName: String? = null,
    val status: TaskStatus,
    val participatedAt: KotlinLocalDateTime? = null,
)

@Serializable
private data class InterveneUserCheckInRequest(
    val userId: String, val interventionType: InterventionType, val soterInfo: SoterResultFromUser? = null
)
