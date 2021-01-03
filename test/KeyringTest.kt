package com.saga.authenticator

import io.ktor.util.*
import org.assertj.core.api.Assertions.*
import org.jose4j.jwk.*
import org.jose4j.jws.*
import org.junit.jupiter.api.*

private const val MAP_NAME = "testMap"

@KtorExperimentalAPI
class KeyringTest {

    private val svc = RedissonKeyStore(mapName = MAP_NAME)
    private val map: MutableMap<String, PublicJsonWebKey> = getRedissonClient().getMap(MAP_NAME)

    private val k1: PublicJsonWebKey = RsaJwkGenerator.generateJwk(512)
    private val k2: PublicJsonWebKey = RsaJwkGenerator.generateJwk(512)

    @BeforeEach
    @AfterEach
    fun cleanup() {
        map.clear()
    }

    @Test
    fun `Can instanciate with empty constructor`() {
        assertDoesNotThrow { RedissonKeyStore() }
    }

    @Test
    fun `Get current key from keyring`() {
        map[CURRENT_KEY] = k1

        val actual = svc.getCurrent()

        assertKeyEquals(actual, k1)
    }

    @Test
    fun `Get previous key from keyring`() {
        map[PREVIOUS_KEY] = k1

        val actual = svc.getPrevious()!!

        assertKeyEquals(actual, k1)
    }

    @Test
    fun `Generate new key when current is null`() {
        val actual = svc.getCurrent()

        assertNewKey(actual)
    }

    @Test
    fun `Key rotation`() {
        map[CURRENT_KEY] = k1
        map[PREVIOUS_KEY] = k2

        val curr = svc.getCurrent()
        val prev: PublicJsonWebKey = svc.getPrevious()!!

        assertKeyEquals(curr, k1)
        assertKeyEquals(prev, k2)

        svc.rotateKeys()

        val newCurr = svc.getCurrent()
        val newPrev: PublicJsonWebKey = svc.getPrevious()!!

        assertNewKey(newCurr)
        assertKeyEquals(newPrev, k1)
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