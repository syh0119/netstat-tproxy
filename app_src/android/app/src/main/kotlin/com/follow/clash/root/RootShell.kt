package com.follow.clash.root

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal data class ShellResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean = false,
) {
    val success: Boolean get() = exitCode == 0 && !timedOut

    fun requireSuccess(operation: String) {
        check(success) {
            val output = RootDiagnostics.redact("$stderr\n$stdout").trim().take(8_192)
            "$operation failed: exit=$exitCode timeout=$timedOut\n$output"
        }
    }
}

internal class RootShell(
    private val outputLimit: Int = 1024 * 1024,
    private val processStarter: (List<String>) -> Process = { ProcessBuilder(it).start() },
    private val cleanupBudget: RootShellCleanupBudget = sharedCleanupBudget,
) {
    private val invoking = AtomicBoolean()
    private val active = AtomicReference<RunningCall?>()

    /** Java callers (RootDnsCache, RootProxySettings) construct with the output bound only. */
    constructor(outputLimit: Int) : this(
        outputLimit,
        { arguments -> ProcessBuilder(arguments).start() },
        sharedCleanupBudget,
    )

    fun cancel() {
        // Process.destroyForcibly() may synchronously close inherited pipes.
        // Cancellation must not wait for those native close/read operations.
        active.get()?.cleanup(stop = true)
    }

    fun root(
        script: String,
        timeoutMs: Long = 2_000,
        input: ByteArray = byteArrayOf(),
    ): ShellResult = execute(listOf("su", "-c", rootCommand(script)), timeoutMs, input)

    fun execute(
        arguments: List<String>,
        timeoutMs: Long = 2_000,
        input: ByteArray = byteArrayOf(),
    ): ShellResult {
        if (!invoking.compareAndSet(false, true)) return busy(arguments, "Concurrent shell invocation")
        if (!cleanupBudget.tryAcquire()) {
            invoking.set(false)
            return busy(arguments, "Shell cleanup capacity exhausted")
        }
        val process =
            try {
                processStarter(arguments)
            } catch (error: Exception) {
                cleanupBudget.release()
                invoking.set(false)
                return ShellResult(127, "", "Executable unavailable: ${error.javaClass.simpleName}: ${error.message}")
                    .also { record(arguments, it) }
            }
        val readers =
            Executors.newFixedThreadPool(3) { runnable ->
                Thread(runnable, "root-tun-shell").apply { isDaemon = true }
            }
        val stdoutBuffer = ByteArrayOutputStream()
        val stderrBuffer = ByteArrayOutputStream()
        val stdout = readers.submit { capture(process.inputStream, stdoutBuffer) }
        val stderr = readers.submit { capture(process.errorStream, stderrBuffer) }
        val writer = readers.submit { runCatching { process.outputStream.use { it.write(input) } } }
        val call = RunningCall(process, readers, writer, cleanupBudget)
        active.set(call)
        var finished = false
        return try {
            finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            if (!finished) call.cleanup(stop = true)
            runCatching { stdout.get(300, TimeUnit.MILLISECONDS) }
            runCatching { stderr.get(300, TimeUnit.MILLISECONDS) }
            ShellResult(
                exitCode = if (finished) process.exitValue() else -1,
                stdout = snapshot(stdoutBuffer),
                stderr = snapshot(stderrBuffer),
                timedOut = !finished || call.cancelled.get(),
            ).also { record(arguments, it) }
        } catch (_: InterruptedException) {
            call.cleanup(stop = true)
            Thread.currentThread().interrupt()
            ShellResult(-1, snapshot(stdoutBuffer), snapshot(stderrBuffer), timedOut = true)
                .also { record(arguments, it) }
        } finally {
            active.compareAndSet(call, null)
            invoking.set(false)
            // Cleanup is submitted before returning, but never awaited here.
            // Its slot stays occupied until all I/O workers have really exited.
            call.cleanup(stop = !finished)
        }
    }

    private fun busy(
        arguments: List<String>,
        reason: String,
    ): ShellResult = ShellResult(125, "", reason).also { record(arguments, it) }

    private fun snapshot(output: ByteArrayOutputStream): String = synchronized(output) { output.toString("UTF-8") }

    private class RunningCall(
        private val process: Process,
        private val readers: ExecutorService,
        private val writer: Future<*>,
        private val budget: RootShellCleanupBudget,
    ) {
        val cancelled = AtomicBoolean()
        private val cleanupStarted = AtomicBoolean()

        fun cleanup(stop: Boolean) {
            if (stop) cancelled.set(true)
            if (!cleanupStarted.compareAndSet(false, true)) return
            try {
                budget.submit {
                    var reusable = false
                    try {
                        writer.cancel(true)
                        readers.shutdownNow()
                        if (stop) runCatching { process.destroyForcibly() }
                        runCatching { process.inputStream.close() }
                        runCatching { process.errorStream.close() }
                        runCatching { process.outputStream.close() }
                        reusable = readers.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    } finally {
                        // A stuck close/read retains its slot instead of allowing
                        // unbounded replacement threads or privileged processes.
                        if (reusable) budget.release()
                    }
                }
            } catch (_: RejectedExecutionException) {
                // Keep the reserved slot on a closed/unavailable cleanup pool.
                // Never retry cleanup synchronously on the caller's thread.
                note("Shell cleanup executor unavailable; capacity retained")
            }
        }
    }

    private fun capture(
        stream: InputStream,
        output: ByteArrayOutputStream,
    ) {
        stream.use {
            val buffer = ByteArray(8192)
            while (true) {
                val count = it.read(buffer)
                if (count < 0) break
                synchronized(output) {
                    val available = outputLimit - output.size()
                    if (available > 0) output.write(buffer, 0, minOf(available, count))
                }
            }
        }
    }

    companion object {
        // At most four calls, twelve I/O workers and four cleanup workers can
        // remain outstanding across all RootShell instances in this process.
        private val sharedCleanupBudget = RootShellCleanupBudget(4)

        internal fun rootCommand(
            script: String,
            busyboxCandidates: List<String> =
                listOf("/data/adb/ksu/bin/busybox", "/data/adb/ap/bin/busybox", "/data/adb/magisk/busybox"),
        ): String =
            "for root_busybox in ${busyboxCandidates.joinToString(" ", transform = ::quote)}; do " +
                "if [ -x \"\$root_busybox\" ]; then export ASH_STANDALONE=1; " +
                "exec \"\$root_busybox\" sh -c ${quote(script)}; fi; done; exec /system/bin/sh -c ${quote(script)}"

        private val observations = ArrayDeque<String>()

        @Synchronized
        fun note(message: String) {
            observations.addLast("${System.currentTimeMillis()} $message")
            if (observations.size > 64) observations.removeFirst()
        }

        @Synchronized
        private fun record(
            arguments: List<String>,
            result: ShellResult,
        ) {
            if (arguments.firstOrNull() != "su") return
            val operation =
                if (arguments ==
                    listOf("su", "-v")
                ) {
                    "su -v"
                } else if (arguments.lastOrNull() == "id -u") {
                    "su -c id -u"
                } else {
                    "su command"
                }
            observations.addLast(
                "${System.currentTimeMillis()} $operation exit=${result.exitCode} timeout=${result.timedOut} stderr=${result.stderr.take(
                    2048,
                )}",
            )
            if (observations.size > 64) observations.removeFirst()
        }

        @Synchronized
        fun diagnosticLog(): String = observations.joinToString("\n")

        fun quote(value: String): String {
            require('\u0000' !in value)
            return "'${value.replace("'", "'\\''")}'"
        }
    }
}

internal class RootShellCleanupBudget(capacity: Int) : AutoCloseable {
    private val permits = Semaphore(capacity)
    private val executor =
        ThreadPoolExecutor(
            capacity,
            capacity,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(capacity),
            { runnable -> Thread(runnable, "root-tun-shell-cleanup").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )

    fun tryAcquire(): Boolean = !executor.isShutdown && permits.tryAcquire()

    fun release() = permits.release()

    fun submit(action: () -> Unit) = executor.execute(action)

    override fun close() {
        executor.shutdown()
        check(executor.awaitTermination(5, TimeUnit.SECONDS)) { "Shell cleanup workers have not exited" }
    }
}
