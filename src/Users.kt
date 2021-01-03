package com.saga.authenticator

import com.mongodb.*
import com.typesafe.config.*
import io.ktor.auth.*
import io.ktor.config.*
import io.ktor.util.*
import org.bson.*
import org.bson.codecs.pojo.annotations.*
import org.litote.kmongo.*
import org.litote.kmongo.coroutine.*
import org.litote.kmongo.reactivestreams.*
import java.util.*

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

@KtorExperimentalAPI
class UserService : AutoCloseable {
    private val client: CoroutineClient
    private val collection: CoroutineCollection<User>

    init {
        val settings = getMongoSettings()
        client = KMongo.createClient(settings = settings).coroutine
        collection = client.getDatabase("saga-auth").getCollection()
    }

    suspend fun findById(id: UUID) = collection.findOne(User::id eq id)

    suspend fun findByEmail(email: String) = collection.findOne(User::email eq email)

    suspend fun save(user: User) = collection.save(user)

    override fun close() = client.close()

}

@KtorExperimentalAPI
fun getMongoSettings(): MongoClientSettings {
    val settingBuilder = MongoClientSettings.builder()
        .applicationName("Saga/Authenticator")
        .uuidRepresentation(UuidRepresentation.JAVA_LEGACY)

    val appConf = HoconApplicationConfig(ConfigFactory.load())

    val connStringProp = appConf.propertyOrNull("mongo.connectionString")
    var connString: String

    if (connStringProp != null)
        connString = connStringProp.getString()
    else {
        val user = appConf.propertyOrNull("mongo.user")
        val password = appConf.propertyOrNull("mongo.password")
        val host = appConf.propertyOrNull("mongo.host")
        val port = appConf.propertyOrNull("mongo.port")
        val authDb = appConf.propertyOrNull("mongo.authDatabase")

        connString = "mongodb://"

        if (user != null && password != null)
            connString += user.getString() + ":" + password.getString() + "@"

        connString += host?.getString() ?: "localhost"
        connString += ":"
        connString += port?.getString() ?: "27017"
        connString += "/"

        if (authDb != null)
            connString += "?authSource=" + authDb.getString()

    }

    settingBuilder.applyConnectionString(ConnectionString(connString))
    return settingBuilder.build()
}