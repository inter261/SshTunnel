package com.example.sshtunnel.core

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** Timer ringan bersama untuk watchdog (timeout koneksi SSH, timeout DNS). */
object Timers {
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "tunnel-timer").apply { isDaemon = true }
    }

    fun schedule(delayMs: Long, task: () -> Unit): ScheduledFuture<*> =
        scheduler.schedule(Runnable { task() }, delayMs, TimeUnit.MILLISECONDS)
}
