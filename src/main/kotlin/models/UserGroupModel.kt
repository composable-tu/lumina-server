package org.lumina.models

import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.javatime.datetime
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.lumina.models.UserRole.*

object Users : Table("users") {
    val userId = text("user_id").uniqueIndex()
    val weixinOpenId = text("weixin_open_id").uniqueIndex()
    val weixinUnionId = text("weixin_union_id").uniqueIndex().nullable()
    val userName = text("user_name")
    val isSoterEnabled = bool("is_soter_enabled").default(false)
    override val primaryKey = PrimaryKey(userId)
}

/**
 * 角色权限
 * @property SUPER_ADMIN 超级管理员（唯一，可转让）
 * @property ADMIN 管理员
 * @property MEMBER 普通成员
 */
enum class UserRole { SUPER_ADMIN, ADMIN, MEMBER }

object Groups : Table("groups") {
    val groupId = text("group_id").uniqueIndex()
    val groupName = text("group_name").nullable()
    val superAdmin =
        reference("super_admin_id", Users.userId, onDelete = ReferenceOption.NO_ACTION) // 超级管理员（只唯一，不可为空，可转让）
    val groupPreAuthTokenSM3 = text("group_pre_auth_token_sm3").nullable()
    val preAuthTokenEndTime = datetime("pre_auth_token_end_time").nullable()
    val createdAt = datetime("created_at")
    override val primaryKey = PrimaryKey(groupId)
}

// 用户-团体关联（多对多）
object UserGroups : Table("user_groups") {
    val userId = reference("user_id", Users.userId, onDelete = ReferenceOption.CASCADE)
    val groupId = reference("group_id", Groups.groupId, onDelete = ReferenceOption.CASCADE)
    val permission = enumeration("permission", UserRole::class).default(MEMBER)
    override val primaryKey = PrimaryKey(userId, groupId)

    init {
        index(true, userId, groupId)
    }
}

fun Transaction.weixinOpenId2UserIdOrNull(weixinOpenId: String): String? {
    val user = Users.selectAll().where { Users.weixinOpenId eq weixinOpenId }.firstOrNull()
    return user?.get(Users.userId)
}


