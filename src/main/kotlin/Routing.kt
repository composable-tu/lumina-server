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
import io.ktor.server.routing.*
import org.lumina.routes.*
import org.lumina.routes.subRoutes.weixinSoterRoute

fun Application.configureRouting(appId: String, appSecret: String) {
    val environment = environment.config.property("ktor.environment").getString()
    routing {
        weixinAuthRoute(appId, appSecret)
        groupRoute(appId, appSecret)
        groupManagerRoute(appId, appSecret)
        approvalRoute(appId, appSecret)
        weixinSoterRoute(appId, appSecret)
        userRoute(appId, appSecret)
        taskRoute(appId, appSecret)
        taskManagerRoute(appId, appSecret)
        if (environment.isDev()) {
            devRoute(appId, appSecret)
        }
    }
}

private fun String.isDev(): Boolean {
    return this == "development" || this == "dev" || this == "test"
}
