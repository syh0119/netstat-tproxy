package com.follow.clash.root

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class RootRuntimeTest {
    private fun moduleReply(
        code: String,
        executed: Boolean = false,
        timedOut: Boolean = false,
    ): RootModuleProtocol.Reply =
        RootModuleProtocol.Reply().apply {
            operation = "runtime-start"
            this.code = code
            exitCode = if (code == "ok") 0 else 1
            this.executed = executed
            this.timedOut = timedOut
        }

    @Test
    fun verifiedModuleSuccessDoesNotExecuteTheLegacyShell() {
        val reply = moduleReply("ok", executed = true).apply { stdout = "supervisor-started\n" }
        val result = RootRuntime.controlledResult(reply) { error("Module success must not be replayed") }
        assertTrue(result.success)
        assertEquals(reply.stdout, result.stdout)
        // A successful manager command still does not establish core/TUN readiness.
        assertFalse(RootRuntime.readyForDns(result))
    }

    @Test
    fun onlyUnavailableOrExplicitPreexecutionCompatibilityRepliesMayUseTheLegacyShell() {
        for (reply in listOf(null, moduleReply("unsupported_operation"), moduleReply("incompatible_version"))) {
            var calls = 0
            val legacy = ShellResult(0, "legacy result", "")
            val result = RootRuntime.controlledResult(reply) { calls++; legacy }
            assertEquals(1, calls)
            assertEquals(legacy, result)
        }
    }

    @Test
    fun rejectedAndUncertainModuleActionsAreNotReplayedEvenWhenNothingWasConfirmed() {
        val replies =
            listOf(
                moduleReply("authorization_denied"),
                moduleReply("authorization_unknown"),
                moduleReply("unauthorized"),
                moduleReply("busy"),
                moduleReply("runtime_untrusted"),
                moduleReply("command_failed", executed = true),
                moduleReply("module_outcome_unknown", executed = true),
                moduleReply("module_peer_untrusted"),
                moduleReply("module_credentials_invalid"),
                moduleReply("module_timed_out", executed = true, timedOut = true),
                moduleReply("module_cancelled", executed = true),
                moduleReply("unsupported_operation", executed = true),
                moduleReply("unsupported_operation", timedOut = true),
                moduleReply("incompatible_version").apply { stdout = "unexpected evidence" },
            )
        for (reply in replies) {
            var calls = 0
            val result = RootRuntime.controlledResult(reply) { calls++; ShellResult(0, "", "") }
            assertEquals(reply.code, 0, calls)
            assertFalse(reply.code, result.success)
            assertTrue(reply.code, result.stderr.contains("do not replay"))
            assertEquals(reply.timedOut, result.timedOut)
        }
    }

    @Test
    fun contradictoryLocalModuleFailureNeverBecomesExitZeroSuccess() {
        val reply = moduleReply("module_outcome_unknown").apply { exitCode = 0 }
        val result = RootRuntime.controlledResult(reply) { error("Unknown result must not be replayed") }
        assertFalse(result.success)
        assertEquals(1, result.exitCode)
    }

    @Test
    fun pairingRequiresTheExactSuccessfulAcknowledgement() {
        val acknowledgement = "module-paired:v1\n"
        assertTrue(RootRuntime.confirmedModulePairing(ShellResult(0, acknowledgement, "")))
        for (result in listOf(
            ShellResult(1, acknowledgement, ""),
            ShellResult(0, acknowledgement, "", timedOut = true),
            ShellResult(0, "", ""),
            ShellResult(0, "module-paired:v2\n", ""),
            ShellResult(0, "banner\n$acknowledgement", ""),
            ShellResult(0, acknowledgement + acknowledgement, ""),
            ShellResult(0, acknowledgement, "permission denied"),
        )) {
            assertFalse(result.toString(), RootRuntime.confirmedModulePairing(result))
        }
    }

    @Test
    fun bufferedHeadCannotConsumeTheFollowingSetting() {
        val directory = Files.createTempDirectory("root-publication-buffered").toFile()
        try {
            val values =
                linkedMapOf(
                    "authorization.sh" to ByteArray(7020) { (it % 251).toByte() },
                    "runtime.sh" to ByteArray(48997) { ((it + 37) % 251).toByte() },
                    "empty" to byteArrayOf(),
                    "last" to "中文\n'$ literal".toByteArray(),
                )
            val (script, input) = RootRuntime.batchPublication(directory.path.replace('\\', '/'), values)
            val readAhead =
                """
                head() {
                    head_input=${'$'}(mktemp ${RootShell.quote("${directory.path.replace('\\', '/')}/head.XXXXXX")})
                    cat >"${'$'}head_input"
                    command head "${'$'}@" "${'$'}head_input"
                    rm -f "${'$'}head_input"
                }
                """.trimIndent()
            val scriptFile = File(directory, "publish.sh").apply { writeText("$readAhead\n$script") }
            val result = RootShell().execute(listOf("sh", scriptFile.path), 5_000, input)
            assertTrue("exit=${result.exitCode}: ${result.stderr}", result.success)
            values.forEach { (name, bytes) -> assertArrayEquals(name, bytes, File(directory, name).readBytes()) }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun incompleteOrExtraPayloadCannotReplaceExistingSettings() {
        val directory = Files.createTempDirectory("root-publication-incomplete").toFile()
        try {
            val values = linkedMapOf("first" to "new first".toByteArray(), "last" to byteArrayOf(0, 1, 2))
            val (script, input) = RootRuntime.batchPublication(directory.path.replace('\\', '/'), values)
            val scriptFile = File(directory, "publish.sh").apply { writeText(script) }
            for (payload in listOf(input.copyOf(input.size - 1), input + byteArrayOf(0))) {
                for (name in values.keys) File(directory, name).writeText("previous")
                val result = RootShell().execute(listOf("sh", scriptFile.path), 5_000, payload)
                assertFalse(result.success)
                assertTrue(result.stderr, result.stderr.contains("root-publication:"))
                for (name in values.keys) assertEquals("previous", File(directory, name).readText())
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun settingsArePublishedInOneShellWithoutDelimiterOrEncodingLoss() {
        val directory = Files.createTempDirectory("root-publication").toFile()
        try {
            val values =
                linkedMapOf(
                    "first" to "中文\n'$ literal".toByteArray(),
                    "empty" to byteArrayOf(),
                    "last" to byteArrayOf(0, 1, 2, 10, 127),
                )
            val (script, input) = RootRuntime.batchPublication(directory.path.replace('\\', '/'), values)
            val scriptFile = File(directory, "publish.sh").apply { writeText(script) }
            val result = RootShell().execute(listOf("sh", scriptFile.path), 5_000, input)
            assertTrue(result.stderr, result.success)
            values.forEach { (name, bytes) -> assertArrayEquals(bytes, File(directory, name).readBytes()) }
            val (truncatedScript, full) =
                RootRuntime.batchPublication(
                    directory.path.replace('\\', '/'),
                    mapOf("incomplete" to byteArrayOf(1, 2, 3)),
                )
            scriptFile.writeText(truncatedScript)
            assertFalse(RootShell().execute(listOf("sh", scriptFile.path), 5_000, full.copyOf(2)).success)
            assertFalse(File(directory, "incomplete").exists())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun dnsProbeWaitsForTheSupervisorsRunningState() {
        for (state in listOf("starting", "recovering", "disabled", "stopping", "failed", "running-invalid")) {
            assertFalse(state, RootRuntime.readyForDns(ShellResult(0, "$state -\nbootMs:1000", "")))
        }
        assertFalse(RootRuntime.readyForDns(ShellResult(1, "running -", "")))
        assertFalse(RootRuntime.readyForDns(ShellResult(0, "running -", "", timedOut = true)))
        assertTrue(RootRuntime.readyForDns(ShellResult(0, "running -\nbootMs:1000", "")))
        assertTrue(RootRuntime.readyForDns(ShellResult(0, "running CORE_RECOVERED", "")))
    }

    @Test
    fun localProbePolicyPrecedesCatchAllAndPreservesUserPolicies() {
        val existing = linkedMapOf<Any?, Any?>("+.*" to listOf("https://resolver.example/dns-query"), "corp.example" to "10.0.0.53")
        val policy = RootRuntime.dnsProbePolicy(existing)
        assertEquals(RootHealth.PROBE_DOMAIN, policy.keys.first())
        assertEquals("rcode://success", policy[RootHealth.PROBE_DOMAIN])
        assertEquals(existing, policy.filterKeys { it != RootHealth.PROBE_DOMAIN })
        assertEquals(2, existing.size)
        assertEquals(mapOf(RootHealth.PROBE_DOMAIN to "rcode://success"), RootRuntime.dnsProbePolicy(null))
    }

    @Test
    fun flutterUppercaseDatabasesAreStagedWithCanonicalNames() {
        val directory = Files.createTempDirectory("root-geo-assets").toFile()
        try {
            for (name in listOf("GEOIP.metadb", "GEOIP.dat", "GEOSITE.dat", "ASN.mmdb")) {
                File(directory, name).writeText(name)
            }
            val assets = RootRuntime.geoAssets(directory)
            assertEquals(setOf("geoip.metadb", "GeoIP.dat", "GeoSite.dat", "ASN.mmdb"), assets.keys)
            assertEquals("GEOIP.metadb", assets.getValue("geoip.metadb").name)
            assertEquals("GEOIP.dat", assets.getValue("GeoIP.dat").readText())
            assertEquals("GEOSITE.dat", assets.getValue("GeoSite.dat").readText())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun mmdbAliasesAndMixedCaseAreSupported() {
        val directory = Files.createTempDirectory("root-geo-aliases").toFile()
        try {
            for (name in listOf("cOuNtRy.MmDb", "gEoIp.Db", "gEoIp.MeTaDb")) {
                val asset = File(directory, name).apply { writeText(name) }
                assertEquals(asset, RootRuntime.geoAssets(directory).getValue("geoip.metadb"))
                asset.delete()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun currentAppDatabaseWinsOverLegacyAliasesAndEmptyFilesAreIgnored() {
        val directory = Files.createTempDirectory("root-geo-selection").toFile()
        try {
            File(directory, "Country.mmdb").writeText("legacy")
            val current = File(directory, "GEOIP.metadb").apply { writeText("current") }
            File(directory, "GeoIP.dat").writeText("")
            File(directory, "GeoSite.dat").mkdir()
            File(directory, "config.yaml").writeText("rules: []")
            assertEquals(mapOf("geoip.metadb" to current), RootRuntime.geoAssets(directory))
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun verifiedDatabaseReplacesInterruptedDownloadAndStaleAliases() {
        val directory = Files.createTempDirectory("root geo publication").toFile()
        try {
            val target = File(directory, "geoip.metadb").apply { writeText("interrupted-download") }
            val stale = File(directory, "Country.mmdb").apply { writeText("stale") }
            val legacy = File(directory, "gEoIp.Db").apply { writeText("stale") }
            File(directory, "geoip.metadb.next").writeText("verified-source")
            val unrelated = File(directory, "provider.metadb").apply { writeText("provider") }
            val nested =
                File(directory, "assets/Country.mmdb").apply {
                    parentFile.mkdirs()
                    writeText("provider-country")
                }
            val script =
                File(directory, "publish.sh").apply {
                    writeText(RootRuntime.publishGeoAsset(directory.path.replace('\\', '/'), "geoip.metadb"))
                }
            val result = RootShell().execute(listOf("sh", script.path), 5_000)
            assertTrue(result.stderr, result.success)
            assertEquals("verified-source", target.readText())
            assertFalse(stale.exists())
            assertFalse(legacy.exists())
            assertEquals("provider", unrelated.readText())
            assertEquals("provider-country", nested.readText())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun failedPublicationPreservesThePreviousDatabase() {
        val directory = Files.createTempDirectory("root-geo-failed-publication").toFile()
        try {
            val previous = File(directory, "Country.mmdb").apply { writeText("previous") }
            val script =
                File(directory, "publish.sh").apply {
                    writeText(RootRuntime.publishGeoAsset(directory.path.replace('\\', '/'), "geoip.metadb"))
                }
            assertFalse(RootShell().execute(listOf("sh", script.path), 5_000).success)
            assertEquals("previous", previous.readText())
        } finally {
            directory.deleteRecursively()
        }
    }
}
