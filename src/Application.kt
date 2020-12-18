package com.saga.authenticator

import at.favre.lib.crypto.bcrypt.*
import com.mongodb.*
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.http.*
import io.ktor.response.*
import io.ktor.routing.*
import org.bson.*
import org.litote.kmongo.coroutine.*
import org.litote.kmongo.reactivestreams.*
import java.util.*

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)


fun Application.module() {
    val settings = MongoClientSettings.builder()
        .applicationName("Authenticator")
        .applyConnectionString(ConnectionString("mongodb+srv://dev:7W0z8OqgiN3TOGhZ@cluster0.llizg.mongodb.net/saga-dev?authSource=admin&replicaSet=atlas-i32jff-shard-0&readPreference=primary&appname=MongoDB%20Compass&ssl=true"))
        .build()
    val mongoClient = KMongo.createClient(settings = settings).coroutine
    val mongoDb = mongoClient.getDatabase("saga-auth")
    val users = mongoDb.getCollection<User>()

//    val conf = Config()
//    conf.useSingleServer().address = "redis://redis-17469.c238.us-central1-2.gce.cloud.redislabs.com:17469"
//    conf.useSingleServer().password = "SuperSecurePassword!"
//    val redisClient = Redisson.create(conf)
//
//    //Key: token, value: user
//    val map: Map<UUID, UUID> = redisClient.getMap("refreshTokens")

    install(Authentication) {
        basic {
            realm = "Sága Authentication Service"
            validate {
                users.findOne(Document.parse("{\"email\": \"" + it.name + "\"}")).takeIf { u ->
                    BCrypt.verifyer().verify(it.password.toByteArray(), u?.passwordHash).verified
                }
            }
        }
    }

    routing {
        authenticate {
            get("/authenticate") {
                call.response.cookies.append(
                    Cookie(
                        "refreshToken",
                        "test-token-value-will-be-uuid",
                        path = "/refresh",
                        httpOnly = true
                    )
                )
                TODO("Create and save real refreshToken and return new JWT here")
            }

            get("/") {
                call.respondText { call.authentication.principal.toString() }
            }
        }

        get("/refresh") {
            call.request.cookies["refreshToken"].let {
                if (it != null)
                    TODO("Return JWT here")
                else
                    call.respond(HttpStatusCode.Unauthorized, "Missing refresh token")
            }
        }

        get("/keys") {
            TODO("Key rotation (creation and purge)")
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
