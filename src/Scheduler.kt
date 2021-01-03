package com.saga.authenticator

import java.util.concurrent.*

data class Every(val n: Long, val unit: TimeUnit)

class ScheduledTask(private val task: Runnable) {
    private val executor = Executors.newScheduledThreadPool(1)

    fun scheduleExecution(every: Every) {
        executor.scheduleWithFixedDelay(task, every.n, every.n, every.unit)
    }


    fun stop() {
        executor.shutdown()

        try {
            executor.awaitTermination(1, TimeUnit.MINUTES)
        } catch (e: InterruptedException) {
            System.err.println(e.localizedMessage)
        }

    }
}
