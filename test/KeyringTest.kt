package com.saga.authenticator

import io.ktor.util.*
import org.assertj.core.api.Assertions.*
import org.jose4j.jwk.*
import org.jose4j.jws.*
import org.junit.jupiter.api.*

private const val MAP_NAME = "testMap"
private val k1 = RsaJwkGenerator.generateJwk(512)
private val k2 = RsaJwkGenerator.generateJwk(512)

interface KeyStoreTest<T : KeyStore> {

    fun getStore(): T
    fun getBackingMap(): MutableMap<String, PublicJsonWebKey>

    @BeforeEach
    @AfterEach
    fun cleanup() = getBackingMap().clear()

    @Test
    fun `Get current key from keyring`() {
        getBackingMap()[CURRENT_KEY] = k1

        val actual = getStore().getCurrent()

        assertKeyEquals(actual, k1)
    }

    @Test
    fun `Get previous key from keyring`() {
        getBackingMap()[PREVIOUS_KEY] = k1

        val actual = getStore().getPrevious()!!

        assertKeyEquals(actual, k1)
    }

    @Test
    fun `Generate new key when current is null`() {
        val actual = getStore().getCurrent()

        assertNewKey(actual)
    }

    @Test
    fun `Key rotation`() {
        getBackingMap()[CURRENT_KEY] = k1
        getBackingMap()[PREVIOUS_KEY] = k2

        val curr = getStore().getCurrent()
        val prev: PublicJsonWebKey = getStore().getPrevious()!!

        assertKeyEquals(curr, k1)
        assertKeyEquals(prev, k2)

        getStore().rotateKeys()

        val newCurr = getStore().getCurrent()
        val newPrev: PublicJsonWebKey = getStore().getPrevious()!!

        assertNewKey(newCurr)
        assertKeyEquals(newPrev, k1)
    }

    @Test
    fun `Test key rotation with null keys`() {
        assertDoesNotThrow { getStore().rotateKeys() }

        val newCurr = getStore().getCurrent()
        val newPrev = getStore().getPrevious()

        assertNewKey(newCurr)
        assertThat(newPrev).isNull()
    }

    @Test
    fun `Get and validate JWKS representation of keys`() {
        getBackingMap()[CURRENT_KEY] = k1
        getBackingMap()[PREVIOUS_KEY] = k2

        val keys = getStore().getJwks().jsonWebKeys

        assertKeyEquals(keys[0] as PublicJsonWebKey, k1)
        assertKeyEquals(keys[1] as PublicJsonWebKey, k2)
    }

}

@KtorExperimentalAPI
class RedissonKeyStoreTest : KeyStoreTest<RedissonKeyStore> {

    private val keystore = RedissonKeyStore(mapName = MAP_NAME, keySize = 512)
    private val backingMap: MutableMap<String, PublicJsonWebKey> = getRedissonClient().getMap(MAP_NAME)

    override fun getStore(): RedissonKeyStore = keystore
    override fun getBackingMap(): MutableMap<String, PublicJsonWebKey> = backingMap

    @Test
    fun `Instanciate using default constructor`() {
        assertDoesNotThrow { RedissonKeyStore() }
    }

}

class MemoryKeyStoreTest : KeyStoreTest<MemoryKeyStore> {

    private val backingMap: MutableMap<String, PublicJsonWebKey> = HashMap()
    private val keystore = MemoryKeyStore(keyMap = backingMap, keySize = 512)

    override fun getStore(): MemoryKeyStore = keystore
    override fun getBackingMap(): MutableMap<String, PublicJsonWebKey> = backingMap


    @Test
    fun `Instanciate using default constructor`() {
        assertDoesNotThrow { MemoryKeyStore() }
    }
}


private fun assertKeyEquals(actual: PublicJsonWebKey, expected: PublicJsonWebKey) {
    assertThat(actual.keyId).isEqualTo(expected.keyId)
    assertThat(actual.publicKey).isEqualTo(expected.publicKey)
    assertThat(actual.privateKey).isEqualTo(expected.privateKey)
    assertThat(actual.algorithm).isEqualTo(expected.algorithm)
}

private fun assertNewKey(actual: PublicJsonWebKey) {
    assertThat(actual.keyId).isNotBlank
    assertThat(actual.publicKey).isNotNull
    assertThat(actual.privateKey).isNotNull
    assertThat(actual.algorithm).isEqualTo(AlgorithmIdentifiers.RSA_PSS_USING_SHA512)
}