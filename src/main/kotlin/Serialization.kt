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

import io.ktor.client.plugins.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.lumina.utils.*

fun Application.configureSerialization() {
    val environment = environment.config.property("ktor.environment").getString()
    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
            ignoreUnknownKeys = true
        })
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            if (environment.isDev()) {
                cause.printStackTrace()
                call.respond(
                    status = HttpStatusCode.InternalServerError, message = ErrorResponse(
                        message = cause.toString().ifEmpty { "服务端错误" },
                        statusCode = HttpStatusCode.InternalServerError.value
                    )
                )
            } else {
                val status = when (cause) {
                    is ResponseException -> cause.response.status
                    else -> HttpStatusCode.InternalServerError
                }

                val message = when (cause) {
                    is LuminaNotFoundException, is LuminaBadRequestException, is LuminaIllegalStateException, is LuminaIllegalArgumentException, is LuminaAuthenticationException -> cause.message
                    else -> "服务端错误"
                }

                call.respond(
                    status = status, message = ErrorResponse(
                        message = message ?: "服务端错误", statusCode = status.value
                    )
                )
            }
            cause.printStackTrace()
            this@configureSerialization.log.error(cause.toString())
        }
    }
}

private fun String.isDev(): Boolean {
    return this == "development" || this == "dev" || this == "test"
}

@Serializable
data class ErrorResponse(
    val message: String, val statusCode: Int
)
