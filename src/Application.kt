package com.saga.authenticator

import at.favre.lib.crypto.bcrypt.*
import com.mongodb.*
import com.typesafe.config.*
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.config.*
import io.ktor.http.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.util.*
import org.bson.*
import org.redisson.*
import org.redisson.api.*
import org.redisson.config.Config
import java.util.*
import javax.annotation.processing.*

typealias NoCoverage = Generated

@NoCoverage
fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
fun Application.module() {
    val users: UserService = MongoUserService()
    val tokens = TokenService()

    install(Authentication) {
        form {
            validate { creds ->
                users.findByEmail(creds.name)
                    .takeIf { user ->
                        passwordMatches(creds.password, user)
                    }
            }
        }
    }

    routing {
        authenticate {
            post("/authenticate") {
                if (call.authentication.principal is User) {
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

            if (isTokenValid) {
                val user = users.findById(UUID.fromString(subjectOrError))
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

fun passwordMatches(password: String, user: User?): Boolean {
    return if (user == null)
        false
    else
        BCrypt.verifyer().verify(password.toByteArray(), user.passwordHash).verified
}

@KtorExperimentalAPI
object RedissonClientInstance {

    val client: RedissonClient

    init {
        val appConf = HoconApplicationConfig(ConfigFactory.load())
        val conf = Config()
        val singleConf = conf.useSingleServer()
        singleConf.address = appConf.property("redis.url").getString()
        singleConf.password = appConf.propertyOrNull("redis.password")?.getString()
        singleConf.connectionMinimumIdleSize = 1
        singleConf.connectionPoolSize = 2
        client = Redisson.create(conf)
    }
}

@KtorExperimentalAPI
fun getRedissonClient(): RedissonClient = RedissonClientInstance.client

@KtorExperimentalAPI
fun getMongoSettings(): MongoClientSettings {
    val appConf = HoconApplicationConfig(ConfigFactory.load())
    val connStringProp = appConf.property("mongo.connectionString")

    return MongoClientSettings.builder()
        .applicationName("Saga/Authenticator")
        .uuidRepresentation(UuidRepresentation.JAVA_LEGACY)
        .applyConnectionString(ConnectionString(connStringProp.getString()))
        .build()
}