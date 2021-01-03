package com.saga.authenticator

import com.typesafe.config.*
import io.ktor.config.*
import io.ktor.util.*
import org.jose4j.jwk.*
import org.jose4j.jws.*
import org.redisson.*
import org.redisson.api.*
import org.redisson.config.Config
import java.io.*
import java.util.*
import java.util.concurrent.*

interface KeyStore : Closeable {
    fun getCurrent(): PublicJsonWebKey
    fun getPrevious(): PublicJsonWebKey?
    fun getJwks(): JsonWebKeySet
}

const val PREVIOUS_KEY = "previous"
const val CURRENT_KEY = "current"

@KtorExperimentalAPI
class RedissonKeyStore(
    mapName: String = "keyMap",
    rotateEvery: Every = Every(35, TimeUnit.MINUTES),
    private val keySize: Int = 4096
) : KeyStore {

    private val redissonClient: RedissonClient = getRedissonClient()
    private val keyMap: MutableMap<String, PublicJsonWebKey>
    private val rotationTask: Runnable
    private val scheduledRotation: ScheduledTask

    init {
        keyMap = redissonClient.getMap(mapName)

        rotationTask = Runnable {
            keyMap[PREVIOUS_KEY] = keyMap[CURRENT_KEY]
            keyMap[CURRENT_KEY] = getNewKey()
        }

        scheduledRotation = ScheduledTask(rotationTask)
        scheduledRotation.scheduleExecution(rotateEvery)
    }

    override fun getCurrent(): PublicJsonWebKey {
        val key = keyMap[CURRENT_KEY]
        return if (key != null)
            key
        else {
            val newKey = getNewKey()
            keyMap[CURRENT_KEY] = newKey
            newKey
        }
    }

    private fun getNewKey(): RsaJsonWebKey {
        val key = RsaJwkGenerator.generateJwk(keySize)
        key.algorithm = AlgorithmIdentifiers.RSA_PSS_USING_SHA512
        key.keyId = UUID.randomUUID().toString()
        return key
    }

    override fun getPrevious(): PublicJsonWebKey? = keyMap[PREVIOUS_KEY]

    override fun getJwks(): JsonWebKeySet = JsonWebKeySet(listOfNotNull(getCurrent(), getPrevious()))

    override fun close() = redissonClient.shutdown()

    fun rotateKeys() = rotationTask.run()
}

@KtorExperimentalAPI
fun getRedissonClient(): RedissonClient {
    val appConf = HoconApplicationConfig(ConfigFactory.load())
    val conf = Config()
    val singleConf = conf.useSingleServer()
    singleConf.address = appConf.property("redis.url").getString()
    singleConf.password = appConf.property("redis.password").getString()
    singleConf.connectionMinimumIdleSize = 1
    singleConf.connectionPoolSize = 2
    return Redisson.create(conf)
}