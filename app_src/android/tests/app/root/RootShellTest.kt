package com.follow.clash.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class RootShellTest {
    @Test
    fun busyboxBootstrapPreservesArgumentsAndStdin() {
        val directory = Files.createTempDirectory("root shell ").toFile()
        try {
            val busybox = File(directory, "busybox")
            busybox.writeText("#!/bin/sh\n[ \"\$1\" = sh ] && [ \"\$ASH_STANDALONE\" = 1 ] || exit 64\nshift\nexec sh \"\$@\"\n")
            val shell = RootShell()
            val path = busybox.path.replace('\\', '/')
            assertTrue(shell.execute(listOf("sh", "-c", "chmod +x ${RootShell.quote(path)}")).success)
            val payload = "literal ' \$(exit 9)\nsecond line"
            val command = RootShell.rootCommand("cat; printf %s ${RootShell.quote(payload)}", listOf("$path.missing", path))
            val bootstrap = File(directory, "bootstrap.sh").apply { writeText(command) }
            val result = shell.execute(listOf("sh", bootstrap.path.replace('\\', '/')), input = "stdin\n".toByteArray())
            assertTrue(result.stderr, result.success)
            assertEquals("stdin\n$payload", result.stdout)
            val fallback = RootShell.rootCommand("printf fallback", listOf("$path.missing")).replace("/system/bin/sh", "sh")
            bootstrap.writeText(fallback)
            assertEquals("fallback", shell.execute(listOf("sh", bootstrap.path.replace('\\', '/'))).stdout)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun failedCommandsKeepBoundedRedactedOutputAndTimeoutEvidence() {
        val error =
            runCatching {
                ShellResult(1, "Parse config error: invalid rule", "secret: private-value\n").requireSuccess("Validate configuration")
            }.exceptionOrNull()
        assertTrue(error is IllegalStateException)
        assertTrue(error!!.message!!.contains("Validate configuration failed: exit=1 timeout=false"))
        assertTrue(error.message!!.contains("invalid rule"))
        assertFalse(error.message!!.contains("private-value"))
        val timedOut = runCatching { ShellResult(0, "x".repeat(20_000), "", true).requireSuccess("Copy asset") }.exceptionOrNull()
        assertTrue(timedOut!!.message!!.contains("timeout=true"))
        assertTrue(timedOut.message!!.length < 8_300)
        ShellResult(0, "", "").requireSuccess("Completed command")
    }

    @Test
    fun quotesMetacharactersAsData() {
        val payload = "a'b;$(exit 9)\nsecond line"
        val result = RootShell().execute(listOf("sh", "-c", "printf %s ${RootShell.quote(payload)}"))
        assertTrue(result.success)
        assertEquals(payload, result.stdout)
    }

    @Test
    fun capturesFailureAndBothStreams() {
        val result = RootShell().execute(listOf("sh", "-c", "echo output; echo error >&2; exit 7"))
        assertEquals(7, result.exitCode)
        assertEquals("output\n", result.stdout)
        assertEquals("error\n", result.stderr)
    }

    @Test
    fun boundsOutputAndTimesOutWithoutWaitingForInheritedPipes() {
        val shell = RootShell()
        val start = System.nanoTime()
        val interrupted = shell.execute(listOf("sh", "-c", "printf critical-evidence; sleep 5"), 50)
        assertTrue(interrupted.timedOut)
        assertEquals("critical-evidence", interrupted.stdout)
        assertTrue((System.nanoTime() - start) / 1_000_000 < 2_000)
        assertTrue(shell.execute(listOf("sh", "-c", "yes x | head -c 2000000")).stdout.length <= 1048576)
        assertEquals(2_000_000, RootShell(4 * 1024 * 1024).execute(listOf("sh", "-c", "yes x | head -c 2000000")).stdout.length)
    }

    @Test(timeout = 10_000)
    fun blockedDestroyAndCloseDoNotExtendTheCallerDeadline() {
        val release = CountDownLatch(1)
        val process = BlockingProcess(release, blockClose = true)
        RootShellCleanupBudget(1).use { budget ->
            try {
                val start = System.nanoTime()
                val result = RootShell(processStarter = { process }, cleanupBudget = budget).execute(listOf("fixture"), 10)
                assertTrue(result.timedOut)
                assertEquals("critical-evidence", result.stdout)
                assertTrue("Caller waited for native cleanup", (System.nanoTime() - start) / 1_000_000 < 2_000)
                assertTrue(process.destroyStarted.await(1, TimeUnit.SECONDS))
            } finally {
                release.countDown()
            }
        }
    }

    @Test(timeout = 10_000)
    fun cleanupCapacityIsCheckedBeforeStartingMoreProcesses() {
        val release = CountDownLatch(1)
        val starts = AtomicInteger()
        RootShellCleanupBudget(2).use { budget ->
            val shell =
                RootShell(
                    processStarter = {
                        starts.incrementAndGet()
                        BlockingProcess(release)
                    },
                    cleanupBudget = budget,
                )
            try {
                repeat(2) { assertTrue(shell.execute(listOf("fixture"), 10).timedOut) }
                repeat(4) {
                    val refused = shell.execute(listOf("fixture"), 10)
                    assertEquals(125, refused.exitCode)
                    assertFalse(refused.success)
                }
                assertEquals("Busy calls must never start a process", 2, starts.get())
            } finally {
                release.countDown()
            }
        }
    }

    @Test(timeout = 10_000)
    fun cancellationIsPromptAndConcurrentCallsNeverStartAnotherProcess() {
        val release = CountDownLatch(1)
        val process = BlockingProcess(release)
        val starts = AtomicInteger()
        val execution = Executors.newSingleThreadExecutor { runnable -> Thread(runnable).apply { isDaemon = true } }
        RootShellCleanupBudget(1).use { budget ->
            val shell =
                RootShell(
                    processStarter = {
                        starts.incrementAndGet()
                        process
                    },
                    cleanupBudget = budget,
                )
            try {
                val result = execution.submit<ShellResult> { shell.execute(listOf("fixture"), 5_000) }
                assertTrue(process.waitStarted.await(2, TimeUnit.SECONDS))
                assertEquals(125, shell.execute(listOf("fixture")).exitCode)
                assertEquals(1, starts.get())
                val start = System.nanoTime()
                shell.cancel()
                assertTrue("cancel waited for destroy/close", (System.nanoTime() - start) / 1_000_000 < 500)
                assertTrue(process.destroyStarted.await(1, TimeUnit.SECONDS))
                release.countDown()
                assertTrue(result.get(3, TimeUnit.SECONDS).timedOut)
            } finally {
                release.countDown()
                execution.shutdownNow()
            }
        }
    }

    @Test(timeout = 10_000)
    fun failedProcessCreationReleasesItsReservedCapacity() {
        RootShellCleanupBudget(1).use { budget ->
            val starts = AtomicInteger()
            val shell =
                RootShell(
                    processStarter = {
                        starts.incrementAndGet()
                        throw java.io.IOException("fixture creation failure")
                    },
                    cleanupBudget = budget,
                )
            repeat(3) { assertEquals(127, shell.execute(listOf("fixture")).exitCode) }
            assertEquals(3, starts.get())
        }
    }

    private class BlockingProcess(
        private val release: CountDownLatch,
        private val blockClose: Boolean = false,
    ) : Process() {
        val waitStarted = CountDownLatch(1)
        val destroyStarted = CountDownLatch(1)
        private val terminated = CountDownLatch(1)
        private val input = blockingStream("critical-evidence".toByteArray())
        private val error = blockingStream(byteArrayOf())
        private val output = ByteArrayOutputStream()

        private fun blockingStream(bytes: ByteArray): InputStream =
            object : ByteArrayInputStream(bytes) {
                override fun close() {
                    if (blockClose) {
                        var interrupted = false
                        while (release.count > 0) {
                            try {
                                release.await()
                            } catch (_: InterruptedException) {
                                interrupted = true
                            }
                        }
                        if (interrupted) Thread.currentThread().interrupt()
                    }
                    super.close()
                }
            }

        override fun getInputStream(): InputStream = input

        override fun getErrorStream(): InputStream = error

        override fun getOutputStream(): OutputStream = output

        override fun waitFor(): Int {
            waitStarted.countDown()
            terminated.await()
            return 137
        }

        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            waitStarted.countDown()
            return terminated.await(timeout, unit)
        }

        override fun exitValue(): Int {
            check(terminated.count == 0L) { "Fixture process is still running" }
            return 137
        }

        override fun isAlive(): Boolean = terminated.count != 0L

        override fun destroy() {
            destroyForcibly()
        }

        override fun destroyForcibly(): Process {
            destroyStarted.countDown()
            release.await()
            terminated.countDown()
            return this
        }
    }

    @Test
    fun snapshotIncludesExplicitNullsAndExactlyEightStates() {
        val snapshot = RootSnapshot().toMap()
        assertEquals(8, TunState.entries.size)
        assertEquals(27, RootCode.entries.size)
        assertTrue(snapshot.containsKey("lastErrorAt"))
        assertNull(snapshot["lastErrorAt"])
        assertEquals(false, snapshot["stale"])
    }
}
