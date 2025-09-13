package org.lumina.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.toJavaLocalDateTime
import kotlinx.datetime.toKotlinLocalDateTime
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SqlExpressionBuilder.eq
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.count
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_GROUP_ID
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_TASK_ID
import org.lumina.fields.ReturnInvalidReasonFields.UNSAFE_CONTENT
import org.lumina.models.Groups
import org.lumina.models.UserGroups
import org.lumina.models.Users
import org.lumina.models.task.*
import org.lumina.models.weixinOpenId2UserIdOrNull
import org.lumina.routes.TaskStatus.*
import org.lumina.utils.LuminaBadRequestException
import org.lumina.utils.LuminaIllegalStateException
import org.lumina.utils.normalized
import org.lumina.utils.security.*
import org.lumina.utils.sm3
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
                    val userId = weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw LuminaBadRequestException(INVALID_JWT)
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
                                    ?: throw LuminaIllegalStateException("服务端错误")
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
                ).normalized()
                val taskName = request.taskName
                val taskType = request.taskType
                val description = request.description
                val endTime = request.endTime.toJavaLocalDateTime()
                val memberPolicy = request.memberPolicy
                val memberPolicyList = request.memberPolicyList ?: emptyList()
                val checkInToken = request.checkInToken
                if (taskName.isEmpty()) return@post call.respond(HttpStatusCode.BadRequest, "请填写任务名")
                if (endTime < LocalDateTime.now()) return@post call.respond(
                    HttpStatusCode.BadRequest, "提交的结束时间已过，请检查结束时间是否填写正确"
                )
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
                    HttpStatusCode.BadRequest, UNSAFE_CONTENT
                )

                protectedRoute(
                    weixinOpenId, groupId, SUPERADMIN_ADMIN_SET, CheckType.GROUP_ID, "创建任务", true, request.soterInfo
                ) {
                    transaction {
                        val userId = weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw LuminaBadRequestException(INVALID_JWT)
                        Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                            ?: throw LuminaBadRequestException(INVALID_GROUP_ID)
                        val taskId = Tasks.insert {
                            it[this.groupId] = groupId
                            it[this.taskName] = taskName
                            it[this.taskType] = taskType
                            it[this.description] = description
                            it[this.endTime] = endTime
                            it[this.memberPolicy] = memberPolicy
                            it[this.createdAt] = LocalDateTime.now()
                            it[this.creator] = userId
                        }[Tasks.taskId]

                        when (taskType) {
                            TaskType.CHECK_IN -> {
                                if (request.checkInType == null) throw LuminaBadRequestException("请完善签到配置")
                                CheckInTaskInfoTable.insert {
                                    it[this.taskId] = taskId
                                    it[this.checkInType] = request.checkInType
                                    if (request.checkInType == CheckInType.TOKEN && !request.checkInToken.isNullOrEmpty()) it[this.checkInTokenSM3] =
                                        request.checkInToken.sm3()
                                }
                            }

                            TaskType.VOTE -> {
                                if (request.voteTaskOption == null) throw LuminaBadRequestException("请完善投票配置")
                                val optionNames = request.voteTaskOption.map { it.optionName }
                                if (optionNames.size != optionNames.distinct().size) throw LuminaBadRequestException("投票选项名称不能重复")

                                VoteTaskInfoTable.insert {
                                    it[this.taskId] = taskId
                                    it[this.maxSelectable] = request.voteMaxSelectable ?: 1
                                    it[this.canRecall] = request.voteCanRecall ?: false
                                    it[this.isResultPublic] = request.isVoteResultPublic ?: true
                                }
                                request.voteTaskOption.forEach { option ->
                                    VoteTaskOptionTable.insert {
                                        it[this.taskId] = taskId
                                        it[this.optionName] = option.optionName
                                        it[this.sortOrder] = option.sortOrder
                                        if (!option.optionDescription.isNullOrEmpty()) it[this.optionDescription] =
                                            option.optionDescription
                                    }
                                }
                            }

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
                            throw LuminaBadRequestException(INVALID_TASK_ID)
                        }
                        val taskInfo = transaction {
                            val userId =
                                weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw LuminaBadRequestException(INVALID_JWT)
                            val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull()
                                ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            val checkInTaskRow =
                                CheckInTaskInfoTable.selectAll().where { CheckInTaskInfoTable.taskId eq taskId }
                                    .firstOrNull() ?: throw LuminaBadRequestException(INVALID_TASK_ID)
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
                    val request = call.receive<TaskCheckInRequest>().normalized()
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
                            throw LuminaBadRequestException(INVALID_TASK_ID)
                        }
                        transaction {
                            val userId =
                                weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw LuminaBadRequestException(INVALID_JWT)
                            val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull()
                                ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            val checkInTaskRow =
                                CheckInTaskInfoTable.selectAll().where { CheckInTaskInfoTable.taskId eq taskId }
                                    .firstOrNull() ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            val taskStatus = getTaskStatus(taskRow, taskId, userId)
                            when (taskStatus) {
                                NOT_REQUIRED -> throw LuminaBadRequestException("您无需参与此任务")
                                PARTICIPATED -> throw LuminaBadRequestException("您已参与此任务")
                                EXPIRED -> throw LuminaBadRequestException("任务已过期")
                                MARK_AS_NOT_PARTICIPANT -> throw LuminaBadRequestException("您已被任务创建者标记为未参与，如有需要，请与任务创建者联系")
                                MARK_AS_PENDING -> throw LuminaBadRequestException("您已被任务创建者暂缓处理，请尽快与任务创建者取得联系")

                                PENDING, MARK_AS_PARTICIPANT -> {
                                    val checkInTaskType = checkInTaskRow[CheckInTaskInfoTable.checkInType]
                                    when (checkInTaskType) {
                                        CheckInType.TOKEN -> {
                                            val checkInTokenSM3 = checkInTaskRow[CheckInTaskInfoTable.checkInTokenSM3]
                                            val checkInTokenSM3FromUser = request.checkInToken?.sm3()
                                            if (checkInTokenSM3FromUser == null || checkInTokenSM3FromUser != checkInTokenSM3) throw LuminaBadRequestException(
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

            route("/vote/{taskId}") {

                // 获取投票信息
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
                        "获取任务 $taskIdString 的投票信息",
                        false
                    ) {
                        val taskId = try {
                            taskIdString.toLong()
                        } catch (_: NumberFormatException) {
                            throw LuminaBadRequestException(INVALID_TASK_ID)
                        }
                        val voteTaskInfo = transaction {
                            val userId =
                                weixinOpenId2UserIdOrNull(weixinOpenId) ?: throw LuminaBadRequestException(INVALID_JWT)
                            val taskRow = Tasks.selectAll().where { Tasks.taskId eq taskId }.firstOrNull()
                                ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            val voteTaskRow =
                                VoteTaskInfoTable.selectAll().where { VoteTaskInfoTable.taskId eq taskId }.firstOrNull()
                                    ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            val groupId = taskRow[Tasks.groupId]
                            val groupName = Groups.selectAll().where { Groups.groupId eq groupId }.firstOrNull()
                                ?.get(Groups.groupName)
                            val creatorId = taskRow[Tasks.creator]
                            val creatorName =
                                Users.selectAll().where { Users.userId eq creatorId }.firstOrNull()?.get(Users.userName)
                            val taskStatus = getTaskStatus(taskRow, taskId, userId)
                            val isVoteResultPublic = voteTaskRow[VoteTaskInfoTable.isResultPublic]
                            val voteTaskOptions: List<VoteTaskOption> = run {
                                val options =
                                    VoteTaskOptionTable.selectAll().where { VoteTaskOptionTable.taskId eq taskId }
                                        .orderBy(VoteTaskOptionTable.sortOrder).toList()

                                // 批量获取所有选项的投票计数
                                val optionIds = options.map { it[VoteTaskOptionTable.optionId] }
                                val voteCounts = mutableMapOf<Long, Int>()
                                val userSelectedOptions = mutableSetOf<Long>()

                                // 已参与或已结束，且允许公开结果的情况下才可查看结果
                                if ((taskStatus == PARTICIPATED || taskStatus == EXPIRED) && isVoteResultPublic) {
                                    val voteCountResults = VoteTaskParticipationRecord.select(
                                            VoteTaskParticipationRecord.selectedOption,
                                            VoteTaskParticipationRecord.selectedOption.count()
                                        ).where { VoteTaskParticipationRecord.selectedOption inList optionIds }
                                        .groupBy(VoteTaskParticipationRecord.selectedOption)

                                    voteCountResults.forEach { result ->
                                        val optionId = result[VoteTaskParticipationRecord.selectedOption]
                                        val count = result[VoteTaskParticipationRecord.selectedOption.count()].toInt()
                                        voteCounts[optionId] = count
                                    }
                                }

                                // 查询用户选择的选项
                                if (taskStatus == PARTICIPATED) {
                                    val userSelections = VoteTaskParticipationRecord.selectAll().where {
                                        (VoteTaskParticipationRecord.taskId eq taskId) and (VoteTaskParticipationRecord.userId eq userId) and (VoteTaskParticipationRecord.selectedOption inList optionIds)
                                    }

                                    userSelections.forEach { result ->
                                        userSelectedOptions.add(result[VoteTaskParticipationRecord.selectedOption])
                                    }
                                }

                                val voteOptions = options.map { option ->
                                    val optionId = option[VoteTaskOptionTable.optionId]
                                    val selectedCount = voteCounts[optionId]
                                    val isSelected =
                                        if (taskStatus == PARTICIPATED) userSelectedOptions.contains(optionId) else null

                                    VoteTaskOption(
                                        option[VoteTaskOptionTable.optionName],
                                        option[VoteTaskOptionTable.sortOrder],
                                        isSelected,
                                        option[VoteTaskOptionTable.optionDescription],
                                        selectedCount
                                    )
                                }
                                return@run voteOptions
                            }

                            VoteTaskInfo(
                                taskIdString,
                                groupId,
                                groupName,
                                taskRow[Tasks.taskName],
                                voteTaskRow[VoteTaskInfoTable.maxSelectable],
                                voteTaskRow[VoteTaskInfoTable.canRecall],
                                isVoteResultPublic,
                                voteTaskOptions,
                                taskRow[Tasks.description],
                                taskRow[Tasks.endTime].toKotlinLocalDateTime(),
                                taskStatus,
                                taskRow[Tasks.createdAt].toKotlinLocalDateTime(),
                                creatorId,
                                creatorName
                            )
                        }
                        call.respond(voteTaskInfo)
                    }
                }

                // 投票
                post {
                    val taskIdString = call.parameters["taskId"]?.trim() ?: return@post call.respond(
                        HttpStatusCode.BadRequest, INVALID_TASK_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    val request = call.receive<TaskVoteRequest>().normalized()
                    protectedRoute(
                        weixinOpenId,
                        taskIdString,
                        SUPERADMIN_ADMIN_MEMBER_SET,
                        CheckType.TASK_ID,
                        "对任务 $taskIdString 投票",
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
                            val voteTaskRow =
                                VoteTaskInfoTable.selectAll().where { VoteTaskInfoTable.taskId eq taskId }.firstOrNull()
                                    ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            val taskStatus = getTaskStatus(taskRow, taskId, userId)
                            when (taskStatus) {
                                NOT_REQUIRED -> throw LuminaBadRequestException("您无需参与此任务")
                                PARTICIPATED -> throw LuminaBadRequestException("您已参与此任务")
                                EXPIRED -> throw LuminaBadRequestException("任务已过期")
                                PENDING -> {
                                    // 验证用户提交的选项是否有效
                                    val maxSelectable = voteTaskRow[VoteTaskInfoTable.maxSelectable]
                                    if (request.voteOptions.isEmpty()) throw LuminaBadRequestException("请至少选择一个选项")
                                    if (request.voteOptions.size > maxSelectable) throw LuminaBadRequestException("最多只能选择 $maxSelectable 个选项")
                                    val validOptions = VoteTaskOptionTable.selectAll().where {
                                        VoteTaskOptionTable.taskId eq taskId
                                    }.associateBy { it[VoteTaskOptionTable.optionName] }
                                    val selectedOptionIds = request.voteOptions.map { optionName ->
                                        validOptions[optionName]?.get(VoteTaskOptionTable.optionId)
                                            ?: throw LuminaBadRequestException("存在无效的投票选项：$optionName")
                                    }

                                    selectedOptionIds.forEach { optionId ->
                                        VoteTaskParticipationRecord.insert {
                                            it[this.taskId] = taskId
                                            it[this.userId] = userId
                                            it[this.selectedOption] = optionId
                                        }
                                    }
                                    TaskParticipationRecord.insert {
                                        it[this.taskId] = taskId
                                        it[this.userId] = userId
                                        it[this.participatedAt] = LocalDateTime.now()
                                    }
                                }

                                else -> throw LuminaBadRequestException("服务端错误")
                            }
                        }
                        call.respond(HttpStatusCode.OK)
                    }
                }

                // 撤回投票
                post("/recall") {
                    val taskIdString = call.parameters["taskId"]?.trim() ?: return@post call.respond(
                        HttpStatusCode.BadRequest, INVALID_TASK_ID
                    )
                    val weixinOpenId =
                        call.principal<JWTPrincipal>()?.get("weixinOpenId")?.trim() ?: return@post call.respond(
                            HttpStatusCode.Unauthorized, INVALID_JWT
                        )
                    val request = call.receive<TaskRecallVoteRequest>().normalized()
                    protectedRoute(
                        weixinOpenId,
                        taskIdString,
                        SUPERADMIN_ADMIN_MEMBER_SET,
                        CheckType.TASK_ID,
                        "撤回对任务 $taskIdString 的投票",
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
                            val voteTaskRow =
                                VoteTaskInfoTable.selectAll().where { VoteTaskInfoTable.taskId eq taskId }.firstOrNull()
                                    ?: throw LuminaBadRequestException(INVALID_TASK_ID)
                            val taskStatus = getTaskStatus(taskRow, taskId, userId)
                            when (taskStatus) {
                                NOT_REQUIRED -> throw LuminaBadRequestException("您无需参与此任务")
                                EXPIRED -> throw LuminaBadRequestException("任务已结束，无法撤回")
                                PENDING -> throw LuminaBadRequestException("您尚未参与此任务，因此无需撤回")
                                PARTICIPATED -> {
                                    if (!voteTaskRow[VoteTaskInfoTable.canRecall]) throw LuminaBadRequestException("该投票任务不允许撤回")
                                    VoteTaskParticipationRecord.deleteWhere {
                                        (VoteTaskParticipationRecord.taskId eq taskId) and (VoteTaskParticipationRecord.userId eq userId)
                                    }
                                    TaskParticipationRecord.deleteWhere {
                                        (TaskParticipationRecord.taskId eq taskId) and (TaskParticipationRecord.userId eq userId)
                                    }
                                }

                                else -> throw LuminaBadRequestException("服务端错误")
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
 * 2. 之后判断此任务是否为签到任务，如果是签到任务且被用户任务创建者干预：
 *     - 若用户被任务创建者标记为未参与状态，直接返回**标记为**未参与状态，即使用户有参与记录也会被认定未参与
 *     - 若用户被任务创建者标记为待定状态，返回**标记为**待定状态
 *     - 若用户被任务创建者标记为已参与状态，如果之前有参与记录则返回已参与，否则返回**标记为**已参与状态
 * 2. 然后判断用户是否参与过此任务，若用户参与过则返回任务状态为已参与；
 * 3. 最后判断任务是否已过期，若已过期则返回任务状态为已过期，未过期则返回任务状态为待参与。
 * @param taskRow
 * @param taskId
 * @param userId
 */
fun Transaction.getTaskStatus(taskRow: ResultRow, taskId: Long, userId: String): TaskStatus {
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
        val checkInTaskInterventionStatus = if (taskRow[Tasks.taskType] == TaskType.CHECK_IN) {
            val checkInTaskCreatorInterventionRecordRow = CheckInTaskCreatorInterventionRecord.selectAll().where {
                (CheckInTaskCreatorInterventionRecord.taskId eq taskId) and (CheckInTaskCreatorInterventionRecord.userId eq userId)
            }.firstOrNull()
            if (checkInTaskCreatorInterventionRecordRow != null) checkInTaskCreatorInterventionRecordRow[CheckInTaskCreatorInterventionRecord.interventionType] else null
        } else null
        val isExpired = taskRow[Tasks.endTime] .isBefore( LocalDateTime.now())
        val userTaskParticipationRecord = TaskParticipationRecord.selectAll().where {
            (TaskParticipationRecord.taskId eq taskId) and (TaskParticipationRecord.userId eq userId)
        }.firstOrNull()

        when (checkInTaskInterventionStatus) {
            InterventionType.MARK_AS_NOT_PARTICIPANT -> MARK_AS_NOT_PARTICIPANT
            InterventionType.MARK_AS_PENDING -> MARK_AS_PENDING
            InterventionType.MARK_AS_PARTICIPANT -> if (userTaskParticipationRecord == null) MARK_AS_PARTICIPANT else PARTICIPATED
            else -> if (userTaskParticipationRecord == null) {
                if (isExpired) EXPIRED else PENDING
            } else PARTICIPATED
        }
    }
}

/**
 * 任务状态
 * @param PENDING 待参与
 * @param PARTICIPATED 已参与
 * @param NOT_REQUIRED 无需参与
 * @param EXPIRED 已过期
 * @param MARK_AS_PARTICIPANT 被任务创建者标记为已参与
 * @param MARK_AS_NOT_PARTICIPANT 被任务创建者标记为未参与（若用户被任务创建者标记为此状态，即使用户有参与记录也会被认定未参与）
 * @param MARK_AS_PENDING 被任务创建者标记为待定
 */
enum class TaskStatus { PENDING, PARTICIPATED, NOT_REQUIRED, EXPIRED, MARK_AS_PARTICIPANT, MARK_AS_NOT_PARTICIPANT, MARK_AS_PENDING }

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

@Serializable
private data class VoteTaskInfo(
    val taskId: String,
    val groupId: String,
    val groupName: String? = null,
    val taskName: String,
    val voteMaxSelectable: Int,
    val voteCanRecall: Boolean,
    val isVoteResultPublic: Boolean,
    val voteTaskOptions: List<VoteTaskOption>,
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
 * @param voteMaxSelectable 投票最多可选项数量
 * @param voteCanRecall 是否允许用户撤回投票
 * @param isVoteResultPublic 是否公开投票结果
 * @param voteTaskOption 投票选项
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

    val checkInType: CheckInType? = null,
    val checkInToken: String? = null,

    val voteMaxSelectable: Int? = null,
    val voteCanRecall: Boolean? = null,
    val isVoteResultPublic: Boolean? = null,
    val voteTaskOption: List<VoteTaskOption>? = null,

    val soterInfo: SoterResultFromUser? = null
)

@Serializable
private data class TaskCheckInRequest(val checkInToken: String? = null)

@Serializable
private data class TaskVoteRequest(val voteOptions: List<String>, val soterInfo: SoterResultFromUser? = null)

@Serializable
private data class TaskRecallVoteRequest(val soterInfo: SoterResultFromUser? = null)

@Serializable
private data class VoteTaskOption(
    val optionName: String,
    val sortOrder: Int,
    val isUserSelected: Boolean? = null,
    val optionDescription: String? = null,
    val voteCount: Int? = null
)
