package org.linlangwen

import io.ktor.server.application.*
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.StdOutSqlLogger
import org.jetbrains.exposed.sql.addLogger
import org.jetbrains.exposed.sql.transactions.transaction
import org.linlangwen.models.Approvals
import org.linlangwen.models.Groups
import org.linlangwen.models.UserGroups
import org.linlangwen.models.Users

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
            Approvals
        )
        tables.forEach { table ->
            SchemaUtils.createMissingTablesAndColumns(table)
        }
    }
}