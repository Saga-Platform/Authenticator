package com.saga.authenticator

import com.nhaarman.mockitokotlin2.*
import io.ktor.util.*
import kotlinx.coroutines.*
import org.assertj.core.api.Assertions.*
import org.bson.conversions.*
import org.junit.jupiter.api.*
import org.junit.jupiter.api.extension.*
import org.litote.kmongo.*
import org.litote.kmongo.coroutine.*
import org.mockito.junit.jupiter.*
import java.util.*

private val expectedUser: User = User(
    UUID.randomUUID(),
    "email@provider.tld",
    "randomHash".toByteArray(),
    emptyMap()
)

interface UserServiceTest<T : UserService> {


    fun getService(): T

    @Test
    fun `Get user by Id`(): Unit = runBlocking {
        val actual = getService().findById(expectedUser.id)

        assertThat(actual).isEqualTo(expectedUser)
    }

    @Test
    fun `Get user by Id with non-existent Id`(): Unit = runBlocking {
        val actual = getService().findById(UUID.fromString("00000000-0000-0000-0000-000000000000"))

        assertThat(actual).isNull()
    }

    @Test
    fun `Get by email`(): Unit = runBlocking {
        val actual = getService().findByEmail(expectedUser.email)

        assertThat(actual).isEqualTo(expectedUser)
    }

    @Test
    fun `Get user by email with non-existent email`(): Unit = runBlocking {
        val actual = getService().findByEmail("notreal@email.fake")

        assertThat(actual).isNull()
    }
}

@KtorExperimentalAPI
@ExtendWith(MockitoExtension::class)
class MongoUserServiceTest : UserServiceTest<MongoUserService> {

    private val client: CoroutineClient = mock()
    private val collection: CoroutineCollection<User> = mock()
    private val service: MongoUserService = MongoUserService(client, collection)

    override fun getService(): MongoUserService = service

    init {
        runBlocking {
            whenever(collection.findOne(User::id eq expectedUser.id)).thenReturn(expectedUser)
            whenever(collection.findOne(User::email eq expectedUser.email)).thenReturn(expectedUser)
        }
    }

    @Test
    fun `Save user`(): Unit = runBlocking {
        getService().save(expectedUser)

        verifyBlocking(collection) {
            save(expectedUser)
        }
    }

    @Test
    fun `Delete user`(): Unit = runBlocking {
        getService().delete(expectedUser)

        verifyBlocking(collection) {
            deleteOne(filter = check { bson: Bson ->
                assertThat(bson).isEqualTo(or(User::id eq expectedUser.id, User::email eq expectedUser.email))
            }, options = any())
        }
    }
}