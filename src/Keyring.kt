package com.saga.authenticator

import io.ktor.util.*
import org.jose4j.jwk.*
import org.jose4j.jws.*
import org.redisson.api.*
import java.util.*
import java.util.concurrent.*
import kotlin.collections.HashMap

const val PREVIOUS_KEY = "previous"
const val CURRENT_KEY = "current"

interface KeyStore {
    fun getCurrent(): PublicJsonWebKey
    fun getPrevious(): PublicJsonWebKey?
    fun getJwks(): JsonWebKeySet
    fun rotateKeys()
}

data class Every(val n: Long, val unit: TimeUnit)

@KtorExperimentalAPI
class RedissonKeyStore(
    mapName: String = "keyMap",
    rotateEvery: Every = Every(35, TimeUnit.MINUTES),
    private val keySize: Int = 4096
) : KeyStore {

    private val redissonClient: RedissonClient = getRedissonClient()
    private val keyMap: MutableMap<String, PublicJsonWebKey>
    private val rotationTask: Runnable
    private val scheduledRotation: ScheduledFuture<*>

    init {
        keyMap = redissonClient.getMap(mapName)

        rotationTask = Runnable {
            val oldKey = keyMap[CURRENT_KEY]
            if (oldKey is PublicJsonWebKey)
                keyMap[PREVIOUS_KEY] = oldKey

            keyMap[CURRENT_KEY] = getNewKey()
        }

        scheduledRotation = Executors.newScheduledThreadPool(1)
            .scheduleWithFixedDelay(rotationTask, rotateEvery.n, rotateEvery.n, rotateEvery.unit)
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

    override fun rotateKeys() = rotationTask.run()
}

class MemoryKeyStore(
    rotateEvery: Every = Every(35, TimeUnit.MINUTES),
    private val keySize: Int = 4096,
    private val keyMap: MutableMap<String, PublicJsonWebKey> = HashMap()
) : KeyStore {
    private val rotationTask: Runnable
    private val scheduledRotation: ScheduledFuture<*>

    init {
        rotationTask = Runnable {
            val oldKey = keyMap[CURRENT_KEY]
            if (oldKey is PublicJsonWebKey)
                keyMap[PREVIOUS_KEY] = oldKey

            keyMap[CURRENT_KEY] = getNewKey()
        }

        scheduledRotation = Executors.newScheduledThreadPool(1)
            .scheduleWithFixedDelay(rotationTask, rotateEvery.n, rotateEvery.n, rotateEvery.unit)
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

    override fun rotateKeys() = rotationTask.run()
}