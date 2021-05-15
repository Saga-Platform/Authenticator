package com.saga.authenticator

import at.favre.lib.crypto.bcrypt.*
import io.ktor.http.*
import io.ktor.server.testing.*
import io.ktor.util.*
import kotlinx.coroutines.*
import org.assertj.core.api.Assertions.*
import org.bson.*
import org.junit.jupiter.api.*
import java.util.*

private val expected = User(
    UUID.randomUUID(),
    "test@user.tld",
    BCrypt.withDefaults().hash(4, "password".toByteArray()),
    emptyMap()
)

@KtorExperimentalAPI
@Disabled
class ApplicationTest {

    @BeforeEach
    fun beforeEach(): Unit = runBlocking {
        val svc = MongoUserService()
        svc.delete(expected)
        svc.save(expected)
    }

    @AfterEach
    fun afterEach(): Unit = runBlocking { MongoUserService().delete(expected) }

    @Test
    fun `Application is not handling root endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Get, "/").apply {
                assertThat(requestHandled).isFalse
            }
        }
    }

    @Test
    fun `Application is handling authentication endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Post, "/authenticate").apply {
                assertThat(requestHandled).isTrue
            }
        }
    }

    @Test
    fun `Authenticate actual user`() {
        withTestApplication({ module() }) {

            handleRequest {
                method = HttpMethod.Post
                uri = "/authenticate"
                addHeader(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                setBody(listOf(Pair("user", expected.email), Pair("password", "password")).formUrlEncode())

            }.apply {
                assertThat(requestHandled).isTrue
                assertThat(response.status()).isEqualTo(HttpStatusCode.OK)
            }
        }
    }

    @Test
    fun `Authenticate non-existent user`() {
        withTestApplication({ module() }) {

            handleRequest {
                method = HttpMethod.Post
                uri = "/authenticate"
                addHeader(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                setBody(listOf(Pair("user", "not@real.fake"), Pair("password", "notTheRightOne")).formUrlEncode())

            }.apply {
                assertThat(requestHandled).isTrue
                assertThat(response.status()).isEqualTo(HttpStatusCode.Unauthorized)
            }
        }
    }

    @Test
    fun `Application is handling refresh endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Get, "/refresh").apply {
                assertThat(requestHandled).isTrue
            }
        }
    }

    @Test
    fun `Obtaining access token from refresh token`() {
        withTestApplication({ module() }) {
            cookiesSession {
                handleRequest {
                    method = HttpMethod.Post
                    uri = "/authenticate"
                    addHeader(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                    setBody(listOf(Pair("user", expected.email), Pair("password", "password")).formUrlEncode())
                }

                handleRequest(HttpMethod.Get, "/refresh").apply {
                    assertThat(requestHandled).isTrue
                    assertThat(response.status()).isEqualTo(HttpStatusCode.OK)
                    assertThat(response.content).isNotEmpty
                }
            }
        }
    }

    @Test
    fun `Obtaining access token from refresh token for non-existent user`() {
        withTestApplication({ module() }) {
            cookiesSession {
                handleRequest {
                    method = HttpMethod.Post
                    uri = "/authenticate"
                    addHeader(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                    setBody(listOf(Pair("user", expected.email), Pair("password", "password")).formUrlEncode())
                }

                runBlocking { MongoUserService().delete(expected) }

                handleRequest(HttpMethod.Get, "/refresh").apply {
                    assertThat(requestHandled).isTrue
                    assertThat(response.status()).isEqualTo(HttpStatusCode.NotFound)
                    assertThat(response.content).contains("User", "doesn't exist")
                }
            }
        }
    }

    @Test
    fun `Obtaining access token with missing refresh token`() {
        withTestApplication({ module() }) {
            cookiesSession {
                handleRequest(HttpMethod.Get, "/refresh").apply {
                    assertThat(requestHandled).isTrue
                    assertThat(response.status()).isEqualTo(HttpStatusCode.BadRequest)
                    assertThat(response.content).contains("Invalid JWT Refresh token: JWT processing failed")
                }
            }
        }
    }

    @Test
    fun `Application is handling keys endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Get, "/keys").apply {
                assertThat(requestHandled).isTrue
            }
        }
    }

    @Test
    fun `Application is handling registering endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Post, "/register").apply {
                assertThat(requestHandled).isTrue
            }
        }
    }
}

@KtorExperimentalAPI
@Disabled
class GlobalHelpFunctionsTest {

    @Test
    fun `Password matches with correct password for user`() {
        val password = "verySecurePassword"

        val user = User(
            UUID.randomUUID(),
            "email@provider.tld",
            BCrypt.withDefaults().hash(10, password.toByteArray()),
            emptyMap()
        )

        assertThat(passwordMatches(password, user)).isTrue
    }

    @Test
    fun `Password matches with wrong password for user`() {
        val password = "verySecurePassword"

        val user = User(
            UUID.randomUUID(),
            "email@provider.tld",
            BCrypt.withDefaults().hash(10, "notAtAllTheSamePassword".toByteArray()),
            emptyMap()
        )

        assertThat(passwordMatches(password, user)).isFalse
    }

    @Test
    fun `Password matches with null user`() {
        val password = "verySecurePassword"

        assertThat(passwordMatches(password, null)).isFalse
    }

    @Test
    fun `Get Redisson instance`() {
        val client = getRedissonClient()

        assertThat(client).isNotNull
    }

    @Test
    fun `Reusing same instance of Redisson client`() {
        assertThat(getRedissonClient()).isEqualTo(getRedissonClient())
    }

    @Test
    fun `Get global MongoClientSettings generated from the config file`() {
        val settings = getMongoSettings()

        assertThat(settings.applicationName).isEqualTo("Saga/Authenticator")
        assertThat(settings.uuidRepresentation).isEqualTo(UuidRepresentation.JAVA_LEGACY)
        assertThat(settings.clusterSettings.hosts).isNotEmpty
    }

}
