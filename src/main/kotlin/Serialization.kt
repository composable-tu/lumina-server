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

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
            ignoreUnknownKeys = true
        })
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            val status = when (cause) {
                is ResponseException -> cause.response.status
                else -> HttpStatusCode.InternalServerError
            }
            call.respond(
                status = status, message = ErrorResponse(
                    message = cause.message ?: "Server Error", statusCode = status.value
                )
            )
        }
    }
}

@Serializable
data class ErrorResponse(
    val message: String, val statusCode: Int
)
