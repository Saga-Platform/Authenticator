package com.saga.authenticator

import com.mongodb.client.result.*
import io.ktor.auth.*
import io.ktor.util.*
import org.bson.codecs.pojo.annotations.*
import org.litote.kmongo.*
import org.litote.kmongo.coroutine.*
import org.litote.kmongo.reactivestreams.*
import java.util.*

@NoCoverage
data class User(
    @BsonId val id: UUID,
    val email: String,
    val passwordHash: ByteArray,
    val permissions: Map<String, List<String>>
) : Principal {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as User

        if (id != other.id) return false
        if (email != other.email) return false
        if (!passwordHash.contentEquals(other.passwordHash)) return false
        if (permissions != other.permissions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + email.hashCode()
        result = 31 * result + passwordHash.contentHashCode()
        result = 31 * result + permissions.hashCode()
        return result
    }
}

interface UserService {
    suspend fun findById(id: UUID): User?

    suspend fun findByEmail(email: String): User?

    suspend fun save(user: User): UpdateResult?

    suspend fun delete(user: User): DeleteResult
}

@KtorExperimentalAPI
class MongoUserService(
    private val client: CoroutineClient = KMongo.createClient(settings = getMongoSettings()).coroutine,
    private val collection: CoroutineCollection<User> = client.getDatabase("saga-auth").getCollection()
) : UserService {

    override suspend fun findById(id: UUID) = collection.findOne(User::id eq id)

    override suspend fun findByEmail(email: String) = collection.findOne(User::email eq email)

    override suspend fun save(user: User) = collection.save(user)

    override suspend fun delete(user: User) = collection.deleteOne(or(User::id eq user.id, User::email eq user.email))
}