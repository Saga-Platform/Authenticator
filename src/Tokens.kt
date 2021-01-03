package com.saga.authenticator

import io.ktor.http.*
import io.ktor.util.*
import org.jose4j.jws.*
import org.jose4j.jwt.*
import org.jose4j.jwt.consumer.*
import org.jose4j.keys.resolvers.*
import java.time.*
import java.util.concurrent.*

@KtorExperimentalAPI
class TokenService : AutoCloseable {

    private val accessKeys: KeyStore = RedissonKeyStore(mapName = "accessKeys")
    private val refreshKeys: KeyStore =
        RedissonKeyStore(mapName = "refreshKeys", rotateEvery = Every(31, TimeUnit.DAYS))

    fun getRefreshTokenAsCookie(user: User): Cookie = Cookie(
        "refreshToken",
        getRefreshToken(user),
        path = "/refresh",
        httpOnly = true
    )

    private fun getRefreshToken(user: User): String {
        val key = refreshKeys.getCurrent()
        val jws = JsonWebSignature()
        val claims = JwtClaims()

        claims.setGeneratedJwtId(64)
        claims.issuer = "saga/auth"
        claims.audience = listOf("saga/auth")
        claims.subject = user.id.toString()
        claims.notBefore = NumericDate.now()
        claims.expirationTime = NumericDate.fromSeconds(ZonedDateTime.now().plusDays(30).toEpochSecond())
        claims.claimsMap.putAll(mapOf(Pair("type", "refresh")))
        claims.setIssuedAtToNow()

        jws.payload = claims.toJson()
        jws.key = key.privateKey
        jws.keyIdHeaderValue = key.keyId
        jws.algorithmHeaderValue = key.algorithm

        return jws.compactSerialization
    }

    fun getAccessToken(user: User): String {
        val key = accessKeys.getCurrent()
        val jws = JsonWebSignature()
        val claims = JwtClaims()

        claims.setGeneratedJwtId(64)
        claims.issuer = "saga/auth"
        claims.audience = listOf("saga/*")
        claims.subject = user.id.toString()
        claims.notBefore = NumericDate.now()
        claims.setExpirationTimeMinutesInTheFuture(15f)
        claims.claimsMap.putAll(
            mapOf(
                Pair("type", "access"),
                Pair("email", user.email)
            )
        )
        claims.claimsMap.putAll(user.permissions)
        claims.setIssuedAtToNow()

        jws.payload = claims.toJson()
        jws.key = key.privateKey
        jws.keyIdHeaderValue = key.keyId
        jws.algorithmHeaderValue = key.algorithm

        return jws.compactSerialization
    }

    fun isRefreshTokenValid(token: String?): Pair<Boolean, Any> {
        val consumer = JwtConsumerBuilder()
            .setAllowedClockSkewInSeconds(5)
            .setExpectedIssuer("saga/auth")
            .setExpectedAudience("saga/auth")
            .setRequireSubject()
            .setRequireJwtId()
            .setRequireIssuedAt()
            .setRequireNotBefore()
            .setRequireExpirationTime()
            .setVerificationKeyResolver(JwksVerificationKeyResolver(refreshKeys.getJwks().jsonWebKeys))
            .build()

        return try {
            val claims = consumer.processToClaims(token)
            Pair(true, claims.subject)
        } catch (e: InvalidJwtException) {
            Pair(false, e.localizedMessage)
        }
    }

    fun getAccessJwksJson(): String = accessKeys.getJwks().toJson()

    override fun close() {
        accessKeys.close()
        refreshKeys.close()
    }
}