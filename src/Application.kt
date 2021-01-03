package com.saga.authenticator

import at.favre.lib.crypto.bcrypt.*
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.http.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.util.*
import java.util.*

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
fun Application.module() {
    val users = UserService()
    val tokens = TokenService()

    environment.monitor.subscribe(ApplicationStopPreparing) {
        users.close()
        tokens.close()
    }

    install(Authentication) {
        basic {
            realm = "Sága Authentication Service"
            validate { creds ->
                users.findByEmail(creds.name)
                    .takeIf { user -> passwordMatches(creds.password, user) }
            }
        }
    }

    routing {
        authenticate {
            get("/authenticate") {
                if (call.authentication.principal !is User)
                    call.respond(HttpStatusCode.InternalServerError, "Principal was not an user, aborting")
                else {
                    val user = call.authentication.principal as User

                    call.response.cookies.append(tokens.getRefreshTokenAsCookie(user))
                    call.respondText(tokens.getAccessToken(user))
                }
            }
        }

        get("/refresh") {
            val token = call.request.cookies["refreshToken"]
            val validationData = tokens.isRefreshTokenValid(token)
            val isTokenValid = validationData.first
            val subjectOrError = validationData.second

            if (isTokenValid && subjectOrError is UUID) {
                val user = users.findById(subjectOrError)
                if (user == null)
                    call.respond(HttpStatusCode.NotFound, "User ${validationData.second} doesn't exist")
                else
                    call.respondText(tokens.getAccessToken(user))
            } else
                call.respond(HttpStatusCode.BadRequest, "Invalid JWT Refresh token: $subjectOrError")
        }

        get("/keys") {
            call.respondText(tokens.getAccessJwksJson())
        }

        post("/register") {
            if (call.parameters["email"] != null && call.parameters["password"] != null) {
                users.save(
                    User(
                        UUID.randomUUID(),
                        call.parameters["email"]!!,
                        BCrypt.withDefaults().hash(10, call.parameters["password"]?.toByteArray()),
                        emptyMap()
                    )
                )
                call.respond(HttpStatusCode.Created)
            } else
                call.respond(HttpStatusCode.BadRequest, "Missing email or password")
        }
    }
}

fun passwordMatches(password: String, user: User?) =
    BCrypt.verifyer().verify(password.toByteArray(), user?.passwordHash).verified