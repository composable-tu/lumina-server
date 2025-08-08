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
    val appId = environment.config.property("wx.appId").getString()
    val appSecret = environment.config.property("wx.appSecret").getString()
    val dbUrl = environment.config.property("db.url").getString()
    val dbUser = environment.config.property("db.user").getString()
    val dbDriver = environment.config.property("db.driver").getString()
    val dbPassword = environment.config.property("db.password").getString()
    val jwtDomain = environment.config.property("jwt.domain").getString()
    val jwtRealm = environment.config.property("jwt.realm").getString()
    val jwtIssuer = environment.config.property("jwt.issuer").getString()
    val jwtAudience = environment.config.property("jwt.audience").getString()
    val signPublicKeyHex = environment.config.property("jwt.sm2.signPublicKey").getString()
    val signPrivateKeyHex = environment.config.property("jwt.sm2.signPrivateKey").getString()

    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
            ignoreUnknownKeys = true
        })
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            println(cause)
            val status = when (cause) {
                is ResponseException -> cause.response.status
                else -> HttpStatusCode.InternalServerError
            }

            val causeMessage =
                cause.message?.replace(appId, "appId")?.replace(appSecret, "appSecret")?.replace(dbUrl, "")?.replace(
                    dbUser, ""
                )?.replace(dbDriver, "")?.replace(dbPassword, "")?.replace(jwtDomain, "")?.replace(jwtRealm, "")
                    ?.replace(jwtIssuer, "")?.replace(jwtAudience, "")?.replace(signPublicKeyHex, "")
                    ?.replace(signPrivateKeyHex, "")
            call.respond(
                status = status, message = ErrorResponse(
                    message = causeMessage ?: "Server Error", statusCode = status.value
                )
            )
        }
    }
}

@Serializable
data class ErrorResponse(
    val message: String, val statusCode: Int
)
