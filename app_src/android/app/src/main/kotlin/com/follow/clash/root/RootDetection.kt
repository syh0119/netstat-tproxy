package com.follow.clash.root

import java.io.File

internal data class RootStatus(
    val manager: String,
    val auth: String,
    val error: RootCode? = null,
)

internal class RootDetection(
    private val shell: RootShell = RootShell(),
    private val managerHint: () -> String? = { null },
    private val moduleAuthorization: () -> ShellResult? = { null },
    private val cancelModule: () -> Unit = {},
    private val versionProbe: () -> ShellResult = { shell.execute(listOf("su", "-v"), 500) },
    private val authorizationProbe: (Long) -> ShellResult = { shell.root("id -u", it) },
) {
    fun detect(
        sdk: Int,
        previousAuth: String = "unknown",
        explicit: Boolean = false,
    ): RootStatus {
        if (sdk < 29) return RootStatus("unknown", "unknown", RootCode.ANDROID_VERSION_UNSUPPORTED)
        // A paired, authenticated module can query Magisk's current policy without su.
        // A denial or indeterminate reply is not permission to prompt/replay via the old path.
        moduleAuthorization()?.let { return fromModuleAuthorization(it) }
        val version = versionProbe()
        val hint = managerHint()
        if (version.exitCode == 127) {
            if (hint in setOf("kernelsu", "apatch")) {
                return RootStatus(checkNotNull(hint), "notGranted", RootCode.ROOT_GRANT_REQUIRED_IN_MANAGER)
            }
            return RootStatus("none", "unknown", RootCode.ROOT_NOT_FOUND)
        }
        val text = (version.stdout + version.stderr).lowercase()
        val manager =
            when {
                "kernelsu" in text || File("/data/adb/ksu").exists() -> "kernelsu"
                "apatch" in text || File("/data/adb/ap").exists() -> "apatch"
                "magisk" in text || File("/data/adb/magisk").exists() -> "magisk"
                else -> hint ?: "unknown"
            }
        if (manager == "unknown") return RootStatus(manager, "unknown", RootCode.ROOT_MANAGER_UNSUPPORTED)
        // Magisk has no portable noninteractive grant query. Only an explicit start may prompt.
        if (manager == "magisk" && !explicit) return RootStatus(manager, previousAuth)
        val result = authorizationProbe(if (manager == "magisk") 30_000 else 1_000)
        val auth =
            when {
                result.success && result.stdout.trim() == "0" -> "granted"
                manager != "magisk" -> "notGranted"
                result.timedOut -> "notGranted"
                else -> "denied"
            }
        val code =
            when {
                auth == "granted" -> null
                manager != "magisk" -> RootCode.ROOT_GRANT_REQUIRED_IN_MANAGER
                result.timedOut -> RootCode.ROOT_PERMISSION_TIMEOUT
                else -> RootCode.ROOT_PERMISSION_DENIED
            }
        return RootStatus(manager, auth, code)
    }

    fun cancel() {
        shell.cancel()
        cancelModule()
    }

    companion object {
        internal fun fromModuleAuthorization(result: ShellResult): RootStatus =
            when {
                result.success && result.stdout.trim() == "0" -> RootStatus("magisk", "granted")
                !result.timedOut &&
                    Regex("permission denied|not allowed|access denied", RegexOption.IGNORE_CASE).containsMatchIn(result.stderr)
                -> RootStatus("magisk", "denied", RootCode.ROOT_PERMISSION_DENIED)
                result.timedOut -> RootStatus("magisk", "unknown", RootCode.ROOT_PERMISSION_TIMEOUT)
                else -> RootStatus("magisk", "unknown", RootCode.ROOT_GRANT_NOT_DETECTED)
            }
    }
}
