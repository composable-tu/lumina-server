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
package org.lumina

import io.ktor.server.application.*
import org.jetbrains.exposed.v1.core.StdOutSqlLogger
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.SchemaUtils
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.lumina.models.*
import org.lumina.models.task.*

fun Application.configureDatabases() {
    val database = Database.connect(
        url = environment.config.property("db.url").getString(),
        user = environment.config.property("db.user").getString(),
        driver = environment.config.property("db.driver").getString(),
        password = environment.config.property("db.password").getString()
    )
    transaction(database) {
        addLogger(StdOutSqlLogger)
        val tables = listOf(
            Users,
            Groups,
            UserGroups,
            Approvals,
            JoinGroupApprovals,
            Tasks,
            TaskMemberPolicies,
            TaskParticipationRecord,
            CheckInTaskInfoTable,
            CheckInTaskCreatorInterventionRecord,
            VoteTaskInfoTable,
            VoteTaskOptionTable,
            VoteTaskParticipationRecord
        )
        tables.forEach { table ->
            SchemaUtils.createMissingTablesAndColumns(table)
        }
    }
}