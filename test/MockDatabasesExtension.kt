package com.saga.authenticator

import de.flapdoodle.embed.mongo.MongodStarter
import de.flapdoodle.embed.mongo.config.MongodConfig
import de.flapdoodle.embed.mongo.config.Net
import de.flapdoodle.embed.mongo.distribution.Version
import de.flapdoodle.embed.process.runtime.Network
import org.junit.jupiter.api.extension.BeforeAllCallback
import org.junit.jupiter.api.extension.ExtensionContext
import redis.embedded.RedisServer

class MockDatabasesExtension : ExtensionContext.Store.CloseableResource, BeforeAllCallback {

    private val redisServer = RedisServer(50000)
    private val mongodExecutable = MongodStarter.getDefaultInstance()
        .prepare(
            MongodConfig.builder()
                .version(Version.Main.PRODUCTION)
                .net(Net(50001, Network.localhostIsIPv6()))
                .build()
        )

    override fun beforeAll(context: ExtensionContext?) {
        val uniqueKey = this.javaClass.name
        val value = context!!.root.getStore(ExtensionContext.Namespace.GLOBAL)[uniqueKey]

        if (value == null) {
            context.root.getStore(ExtensionContext.Namespace.GLOBAL).put(uniqueKey, this)

            println("Starting embedded DBs")
            mongodExecutable.start()
            redisServer.start()

        }
    }

    override fun close() {
        println("Stopping embedded DBs")
        mongodExecutable.stop()
        redisServer.stop()
    }

}