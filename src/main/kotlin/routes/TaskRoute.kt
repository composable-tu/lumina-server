package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.toJavaLocalDateTime
import kotlinx.datetime.toKotlinLocalDateTime
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_GROUP_ID
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_TASK_ID
import org.lumina.models.*
import org.lumina.routes.TaskStatus.*
import org.lumina.utils.*
import org.lumina.utils.security.*
import java.time.LocalDateTime
import kotlinx.datetime.LocalDateTime as KotlinLocalDateTime

fun Route.taskRoute(appId: String, appSecret: String) {
    authenticate {
        route("/task") {
            // 获取用户收到的任务列表
            get {
                val weixinOpenId =
                    call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                        HttpStatusCode.Unauthorized, INVALID_JWT
                    )
                val taskList: List<TaskInfo> = transaction {
                    val userId = weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw BadRequestException(INVALID_JWT)
                    val userGroupList = UserGroups.selectAll().where { UserGroups.userId eq userId }
                    if (userGroupList.toList().isEmpty()) return@transaction emptyList()
                    val taskMutableList = mutableListOf<TaskInfo>()
                    userGroupList.forEach { userGroup ->
                        val groupId = userGroup[UserGroups.groupId]
                        val taskList = Tasks.selectAll().where { Tasks.groupId eq groupId }
                        taskList.forEach { task ->
                            val taskId = task[Tasks.taskId]
                            val creatorRow =
                                Users.selectAll().where { Users.userId eq task[Tasks.creator] }.firstOrNull()
                                    ?: throw IllegalStateException("服务器错误")
                            val creatorName = creatorRow[Users.userName]
                            val taskStatus = getTaskStatus(task, taskId, userId)
                            taskMutableList.add(
                                TaskInfo(
                                    taskId.toString(),
                                    task[Tasks.groupId],
                                    task[Tasks.taskName],
                                    task[Tasks.taskType],
                                    task[Tasks.description],
                                    task[Tasks.endTime].toKotlinLocalDateTime(),
                                    taskStatus,
                                    task[Tasks.createdAt].toKotlinLocalDateTime(),
                                    task[Tasks.creator],
                                    creatorName
                                )
                            )
                        }
                    }
                    taskMutableList.toList()
                }
                return@get call.respond(taskList)
            }

            // 创建任务
            post("/create/{groupId}") {
                val groupId = call.parameters["groupId"]?.trim() ?: return@post call.respond(
                    HttpStatusCode.BadRequest, INVALID_GROUP_ID
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

                val request = Json.decodeFromString<CreateTaskRequest>(
                    weixinDecryptContent(appId, appSecret, weixinUserCryptoKeyRequest)
                ).normalized() as CreateTaskRequest
                val taskName = request.taskName
                val taskType = request.taskType
                val description = request.description
                val endTime = request.endTime
                val memberPolicy = request.memberPolicy
                val memberPolicyList = request.memberPolicyList ?: emptyList()
                val checkInToken = request.checkInToken
                if (taskName.isEmpty()) return@post call.respond(HttpStatusCode.BadRequest, "请填写任务名")
                if (request.checkInType == CheckInType.TOKEN && request.checkInToken.isNullOrEmpty()) return@post call.respond(
                    HttpStatusCode.BadRequest, "请填写签到验证码"
                )
                if (memberPolicy == MemberPolicyType.WHITELIST && request.memberPolicyList.isNullOrEmpty()) return@post call.respond(
                    HttpStatusCode.BadRequest, "白名单模式下，白名单不可为空"
                )

                val isContentSafety = temporaryWeixinContentSecurityCheck(
                    appId, appSecret, WeixinContentSecurityRequest(
                        content = if (!description.isNullOrEmpty()) description else if (!checkInToken.isNullOrEmpty()) checkInToken else taskName,
                        scene = WeixinContentSecurityScene.SCENE_FORUM,
                        title = taskName,
                        openid = weixinOpenId,
                    )
                )
                if (!isContentSafety) return@post call.respond(
                    HttpStatusCode.BadRequest, "您提交的内容被微信判定为存在违规内容，请修改后再次提交"
                )

                protectedRoute(
                    weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, "创建任务", true, request.soterInfo
                ) {
                    transaction {
                        val userId = weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw BadRequestException(INVALID_JWT)
                        Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                            ?: throw BadRequestException(INVALID_GROUP_ID)
                        val taskId = Tasks.insert {
                            it[this.groupId] = groupId
                            it[this.taskName] = taskName
                            it[this.taskType] = taskType
                            it[this.description] = description
                            it[this.endTime] = endTime.toJavaLocalDateTime()
                            it[this.memberPolicy] = memberPolicy
                            it[this.createdAt] = LocalDateTime.now()
                            it[this.creator] = userId
                        }[Tasks.taskId]

                        when (taskType) {
                            TaskType.CHECK_IN -> CheckInTaskInfoTable.insert {
                                it[this.taskId] = taskId
                                it[this.checkInType] = request.checkInType
                                if (request.checkInType == CheckInType.TOKEN && !request.checkInToken.isNullOrEmpty()) it[this.checkInTokenSM3] =
                                    request.checkInToken.sm3()
                            }

                            TaskType.VOTE -> TODO()
                            TaskType.LOTTERY -> TODO()
                        }

                        memberPolicyList.forEach { userInfo ->
                            TaskMemberPolicies.insert {
                                it[TaskMemberPolicies.taskId] = taskId
                                it[TaskMemberPolicies.userId] = userInfo.userId
                            }
                        }
                    }
                    call.respond(HttpStatusCode.OK)
                }
            }
            route("/checkIn/{taskId}") {

                // 获取签到任务信息
                get {
                    val taskIdString = call.parameters["taskId"]?.trim() ?: return@get call.respond(
                        HttpStatusCode.BadRequest, INVALID_TASK_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@get call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    protectedRoute(
                        weixinOpenId,
                        taskIdString,
                        SUPERADMIN_ADMIN_MEMBER_SET,
                        CheckType.TASK_ID,
                        "获取 $taskIdString 签到任务信息",
                        false
                    ) {
                        val taskId = try {
                            taskIdString.toLong()
                        } catch (_: NumberFormatException) {
                            throw BadRequestException(INVALID_TASK_ID)
                        }
                        val taskInfo = transaction {
                            val userId =
                                weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw BadRequestException(INVALID_JWT)
                            val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull()
                                ?: throw BadRequestException(INVALID_TASK_ID)
                            val checkInTaskRow =
                                CheckInTaskInfoTable.selectAll().where { CheckInTaskInfoTable.taskId eq taskId }
                                    .firstOrNull() ?: throw BadRequestException(INVALID_TASK_ID)
                            val groupId = taskRow[Tasks.groupId]
                            val groupName = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                                ?.get(Groups.groupName)
                            val creatorId = taskRow[Tasks.creator]
                            val creatorName =
                                Users.selectAll().where { Users.userId eq creatorId }.firstOrNull()?.get(Users.userName)
                            CheckInTaskInfo(
                                taskIdString,
                                groupId,
                                groupName,
                                taskRow[Tasks.taskName],
                                checkInTaskRow[CheckInTaskInfoTable.checkInType],
                                taskRow[Tasks.description],
                                taskRow[Tasks.endTime].toKotlinLocalDateTime(),
                                getTaskStatus(taskRow, taskId, userId),
                                taskRow[Tasks.createdAt].toKotlinLocalDateTime(),
                                creatorId,
                                creatorName
                            )
                        }
                        call.respond(taskInfo)
                    }
                }

                // 执行签到操作
                post {
                    val taskIdString = call.parameters["taskId"]?.trim() ?: return@post call.respond(
                        HttpStatusCode.BadRequest, INVALID_TASK_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    val request = call.receive<TaskCheckInRequest>().normalized() as TaskCheckInRequest
                    protectedRoute(
                        weixinOpenId,
                        taskIdString,
                        SUPERADMIN_ADMIN_MEMBER_SET,
                        CheckType.TASK_ID,
                        "开始签到 $taskIdString",
                        false
                    ) {
                        val taskId = try {
                            taskIdString.toLong()
                        } catch (_: NumberFormatException) {
                            throw BadRequestException(INVALID_TASK_ID)
                        }
                        transaction {
                            val userId =
                                weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw BadRequestException(INVALID_JWT)
                            val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull()
                                ?: throw BadRequestException(INVALID_TASK_ID)
                            val checkInTaskRow =
                                CheckInTaskInfoTable.selectAll().where { CheckInTaskInfoTable.taskId eq taskId }
                                    .firstOrNull() ?: throw BadRequestException(INVALID_TASK_ID)
                            val taskStatus = getTaskStatus(taskRow, taskId, userId)
                            when (taskStatus) {
                                NOT_REQUIRED -> throw BadRequestException("您无需参与此任务")
                                PARTICIPATED -> throw BadRequestException("您已参与此任务")
                                EXPIRED -> throw BadRequestException("任务已过期")
                                PENDING -> {
                                    val checkInTaskType = checkInTaskRow[CheckInTaskInfoTable.checkInType]
                                    when (checkInTaskType) {
                                        CheckInType.TOKEN -> {
                                            val checkInTokenSM3 = checkInTaskRow[CheckInTaskInfoTable.checkInTokenSM3]
                                            val checkInTokenSM3FromUser = request.checkInToken?.sm3()
                                            if (checkInTokenSM3FromUser == null || checkInTokenSM3FromUser != checkInTokenSM3) throw BadRequestException(
                                                "签到验证码错误"
                                            )
                                        }

                                        else -> Unit
                                    }
                                    TaskParticipationRecord.insert {
                                        it[this.taskId] = taskId
                                        it[this.userId] = userId
                                        it[this.participatedAt] = LocalDateTime.now()
                                    }
                                }
                            }
                        }
                        call.respond(HttpStatusCode.OK)
                    }
                }
            }
        }
    }
}

/**
 * 获取任务状态
 *
 * 1. 首先判断用户是否在任务参与列表中时，若不在直接返回任务状态为无需参与；
 * 2. 然后判断用户是否参与过此任务，若用户参与过则返回任务状态为已参与；
 * 3. 最后判断任务是否已过期，若已过期则返回任务状态为已过期，未过期则返回任务状态为待参与。
 * @param taskRow
 * @param taskId
 * @param userId
 */
private fun Transaction.getTaskStatus(taskRow: ResultRow, taskId: Long, userId: String): TaskStatus {
    val isUserInTask = run {
        val taskMemberPolicy = taskRow[Tasks.memberPolicy]
        val memberList = TaskMemberPolicies.selectAll().where {
            TaskMemberPolicies.taskId eq taskId
        }
        when (taskMemberPolicy) {
            MemberPolicyType.WHITELIST -> memberList.any { member ->
                member[TaskMemberPolicies.userId] == userId
            }

            MemberPolicyType.BLACKLIST -> memberList.none { member ->
                member[TaskMemberPolicies.userId] == userId
            }
        }
    }
    return if (!isUserInTask) NOT_REQUIRED else {
        val isExpired = taskRow[Tasks.endTime] < LocalDateTime.now()
        val userTaskParticipationRecord = TaskParticipationRecord.selectAll().where {
            (TaskParticipationRecord.taskId eq taskId) and (TaskParticipationRecord.userId eq userId)
        }.firstOrNull()
        if (userTaskParticipationRecord == null) {
            if (isExpired) EXPIRED else PENDING
        } else PARTICIPATED
    }
}

/**
 * 任务状态
 * @param PENDING 待参与
 * @param PARTICIPATED 已参与
 * @param NOT_REQUIRED 无需参与
 * @param EXPIRED 已过期
 */
enum class TaskStatus { PENDING, PARTICIPATED, NOT_REQUIRED, EXPIRED }

@Serializable
private data class TaskInfo(
    val taskId: String,
    val groupId: String,
    val taskName: String,
    val taskType: TaskType,
    val description: String? = null,
    val endTime: KotlinLocalDateTime,
    val status: TaskStatus,
    val createdAt: KotlinLocalDateTime,
    val creatorId: String,
    val creatorName: String? = null
)

@Serializable
private data class CheckInTaskInfo(
    val taskId: String,
    val groupId: String,
    val groupName: String? = null,
    val taskName: String,
    val checkInType: CheckInType,
    val description: String? = null,
    val endTime: KotlinLocalDateTime,
    val status: TaskStatus,
    val createdAt: KotlinLocalDateTime,
    val creatorId: String,
    val creatorName: String? = null,
)

/**
 * 创建任务
 * @param taskName 任务名
 * @param taskType 任务类型
 * @param description 描述
 * @param endTime 结束时间
 * @param memberPolicy 成员策略
 * @param memberPolicyList 成员策略列表
 * @param checkInType 签到类型
 * @param checkInToken 签到验证码
 * @param soterInfo SOTER 生物验证信息
 */
@Serializable
private data class CreateTaskRequest(
    val taskName: String,
    val taskType: TaskType,
    val description: String? = null,
    val endTime: KotlinLocalDateTime,
    val memberPolicy: MemberPolicyType,
    val memberPolicyList: List<UserInfo>? = null,
    val checkInType: CheckInType,
    val checkInToken: String? = null,
    val soterInfo: SoterResultFromUser? = null
)

@Serializable
private data class TaskCheckInRequest(
    val checkInToken: String? = null,
)
