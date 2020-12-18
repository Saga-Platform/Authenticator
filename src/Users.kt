package com.saga.authenticator

import io.ktor.auth.*
import java.util.*

data class User(
    val id: UUID,
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