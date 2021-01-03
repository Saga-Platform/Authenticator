package com.saga.authenticator

import io.ktor.http.*
import io.ktor.server.testing.*
import io.ktor.util.*
import kotlinx.coroutines.*
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.*

@KtorExperimentalAPI
class ApplicationTest {

    @Test
    fun `Application is launching sucessfully`() {
        withTestApplication({ module() }) {
            assertThat(this.engine.isActive).isTrue
        }
    }

    @Test
    fun `Application is not handling root endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Get, "/").apply {
                assertThat(this.requestHandled).isFalse
            }
        }
    }

    @Test
    fun `Application is handling authentication endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Get, "/authenticate").apply {
                assertThat(this.requestHandled).isTrue
            }
        }
    }

    @Test
    fun `Application is handling refresh endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Get, "/refresh").apply {
                assertThat(this.requestHandled).isTrue
            }
        }
    }

    @Test
    fun `Application is handling keys endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Get, "/keys").apply {
                assertThat(this.requestHandled).isTrue
            }
        }
    }

    @Test
    fun `Application is handling registering endpoint`() {
        withTestApplication({ module() }) {
            handleRequest(HttpMethod.Post, "/register").apply {
                assertThat(this.requestHandled).isTrue
            }
        }
    }
}
