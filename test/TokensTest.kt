package com.saga.authenticator

import io.ktor.util.*
import org.assertj.core.api.Assertions.*
import org.jose4j.jws.*
import org.jose4j.jwt.*
import org.jose4j.jwt.consumer.*
import org.jose4j.keys.resolvers.*
import org.junit.jupiter.api.*
import java.time.*
import java.util.*
import java.util.concurrent.*

@KtorExperimentalAPI
class TokensTest {

    private val accessKeys: KeyStore = MemoryKeyStore()
    private val refreshKeys: KeyStore = MemoryKeyStore()
    private val svc = TokenService(accessKeys, refreshKeys)

    private val refreshConsumer = JwtConsumerBuilder()
        .setExpectedIssuer("saga/auth")
        .setExpectedAudience("saga/auth")
        .setRequireSubject()
        .setRequireJwtId()
        .setRequireIssuedAt()
        .setRequireNotBefore()
        .setRequireExpirationTime()
        .setVerificationKeyResolver(JwksVerificationKeyResolver(refreshKeys.getJwks().jsonWebKeys))
        .build()

    private val accessConsumer = JwtConsumerBuilder()
        .setExpectedIssuer("saga/auth")
        .setExpectedAudience("saga/*")
        .setRequireSubject()
        .setRequireJwtId()
        .setRequireIssuedAt()
        .setRequireNotBefore()
        .setRequireExpirationTime()
        .setVerificationKeyResolver(JwksVerificationKeyResolver(accessKeys.getJwks().jsonWebKeys))
        .build()

    private val user = User(
        UUID.randomUUID(),
        "email@provider.tld",
        "randomHash".toByteArray(),
        emptyMap()
    )

    @Test
    fun `Get refresh token cookie with proper CSRF settings`() {
        val cookie = svc.getRefreshTokenAsCookie(user)
        val token = cookie.value
        val claims = refreshConsumer.processToClaims(token).claimsMap

        assertThat(cookie)
            .isNotNull
            .hasFieldOrPropertyWithValue("name", "refreshToken")
            .hasFieldOrPropertyWithValue("path", "/refresh")
            .hasFieldOrPropertyWithValue("httpOnly", true)

        assertThat(claims)
            .isNotEmpty
            .containsAllEntriesOf(
                mapOf(
                    Pair("type", "refresh"),
                    Pair("iss", "saga/auth"),
                    Pair("aud", "saga/auth"),
                    Pair("sub", user.id.toString()),
                    Pair("exp", (claims["nbf"] as Long) + TimeUnit.DAYS.toSeconds(30))
                )
            )
    }

    @Test
    fun `Validate refresh token`() {
        val token = svc.getRefreshToken(user)

        val actual = svc.isRefreshTokenValid(token)
        val actualValidity = actual.first
        val actualSubject = actual.second

        assertThat(actualValidity).isTrue
        assertThat(actualSubject).isEqualTo(user.id.toString())
    }

    @Test
    fun `Validate bad refresh token`() {
        val token = generateBadRefreshToken()

        val actual = svc.isRefreshTokenValid(token)
        val actualValidity = actual.first
        val actualSubject = actual.second

        assertThat(actualValidity).isFalse
        assertThat(actualSubject)
            .isNotEqualTo(user.id.toString())
            .contains("rejected")
    }

    @Test
    fun `Get access token`() {
        val token = svc.getAccessToken(user)
        val claims = accessConsumer.processToClaims(token).claimsMap

        assertThat(claims)
            .isNotEmpty
            .containsAllEntriesOf(
                mapOf(
                    Pair("type", "access"),
                    Pair("email", user.email),
                    Pair("iss", "saga/auth"),
                    Pair("aud", "saga/*"),
                    Pair("sub", user.id.toString()),
                    Pair("exp", (claims["nbf"] as Long) + 900),
                    Pair("exp", (claims["nbf"] as Long) + TimeUnit.MINUTES.toSeconds(15))

                )
            )
    }

    private fun generateBadRefreshToken(): String {
        val key = refreshKeys.getCurrent()
        val jws = JsonWebSignature()
        val claims = JwtClaims()

        claims.setGeneratedJwtId(64)
        claims.issuer = "bad/svc"
        claims.audience = listOf("saga/auth")
        claims.subject = UUID.randomUUID().toString()
        claims.notBefore = NumericDate.fromSeconds(350)
        claims.expirationTime = NumericDate.fromSeconds(ZonedDateTime.now().plusDays(30).toEpochSecond())
        claims.setIssuedAtToNow()

        jws.payload = claims.toJson()
        jws.key = key.privateKey
        jws.keyIdHeaderValue = key.keyId
        jws.algorithmHeaderValue = key.algorithm

        return jws.compactSerialization
    }
}