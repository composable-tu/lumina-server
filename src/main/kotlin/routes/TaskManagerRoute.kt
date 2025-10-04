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
package org.lumina.routes

import io.ktor.server.auth.*
import io.ktor.server.routing.*
import org.lumina.routes.taskManagerRoutes.checkInManagerRoute
import org.lumina.routes.taskManagerRoutes.voteManagerRoute

fun Route.taskManagerRoute(appId: String, appSecret: String) {
    authenticate {
        route("/taskManager") {
            route("/checkIn/{taskId}") { checkInManagerRoute(appId, appSecret) }
            route("/vote/{taskId}") { voteManagerRoute() }
        }
    }
}
