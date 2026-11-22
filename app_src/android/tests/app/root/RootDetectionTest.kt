package com.follow.clash.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RootDetectionTest {
    private fun moduleOnly(result: ShellResult): RootDetection =
        RootDetection(
            moduleAuthorization = { result },
            versionProbe = { error("A module reply must not fall back to su -v") },
            authorizationProbe = { error("A module reply must not fall back to su -c id -u") },
        )

    @Test
    fun pairedModuleGrantIsRecheckedWithoutSuForBackgroundAndExplicitDetection() {
        for (explicit in listOf(false, true)) {
            val result = moduleOnly(ShellResult(0, "0\n", "")).detect(29, explicit = explicit)
            assertEquals("magisk", result.manager)
            assertEquals("granted", result.auth)
            assertNull(result.error)
        }
    }

    @Test
    fun moduleDenialDoesNotTriggerAnExplicitRootPrompt() {
        for (explicit in listOf(false, true)) {
            val result = moduleOnly(ShellResult(126, "", "permission denied")).detect(29, explicit = explicit)
            assertEquals("denied", result.auth)
            assertEquals(RootCode.ROOT_PERMISSION_DENIED, result.error)
        }
    }

    @Test
    fun unknownTimeoutAndContradictoryGrantEvidenceAreNeverAcceptedOrReplayed() {
        for (reply in listOf(
            ShellResult(1, "", "authorization unknown"),
            ShellResult(0, "", ""),
            ShellResult(0, "10001\n", ""),
            ShellResult(1, "0\n", ""),
            ShellResult(0, "0\n", "", timedOut = true),
        )) {
            val result = moduleOnly(reply).detect(29, explicit = true)
            assertEquals(reply.toString(), "unknown", result.auth)
            assertEquals(
                if (reply.timedOut) RootCode.ROOT_PERMISSION_TIMEOUT else RootCode.ROOT_GRANT_NOT_DETECTED,
                result.error,
            )
        }
    }

    @Test
    fun unsupportedAndroidDoesNotProbeEitherControlPath() {
        val detection =
            RootDetection(
                moduleAuthorization = { error("Unsupported Android must not query the module") },
                versionProbe = { error("Unsupported Android must not query su") },
                authorizationProbe = { error("Unsupported Android must not authorize") },
            )
        assertEquals(RootCode.ANDROID_VERSION_UNSUPPORTED, detection.detect(28).error)
    }

    @Test
    fun unavailableModulePreservesTheExplicitOnlyMagiskAuthorizationFlow() {
        var versionCalls = 0
        var authorizationCalls = 0
        val detection =
            RootDetection(
                moduleAuthorization = { null },
                versionProbe = { versionCalls++; ShellResult(0, "MAGISKSU\n", "") },
                authorizationProbe = { timeout ->
                    assertEquals(30_000L, timeout)
                    authorizationCalls++
                    ShellResult(0, "0\n", "")
                },
            )
        assertEquals("unknown", detection.detect(29).auth)
        assertEquals(0, authorizationCalls)
        assertEquals("granted", detection.detect(29, explicit = true).auth)
        assertEquals(2, versionCalls)
        assertEquals(1, authorizationCalls)
    }

    @Test
    fun cancelPropagatesToActiveModuleRequests() {
        var cancelled = false
        val detection = RootDetection(cancelModule = { cancelled = true })
        assertFalse(cancelled)
        detection.cancel()
        assertTrue(cancelled)
    }
}
