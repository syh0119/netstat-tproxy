package com.follow.clash.root;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Assume;
import org.junit.AssumptionViolatedException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/** Runs on the host JVM; never invokes su, Android networking or a phone. */
public class RootModuleProtocolTest {
    private static final String ID = "12345678-1234-4234-8234-123456789abc";
    private static final String TOKEN = repeat("a", 64);

    @Test public void fixedRequestHasLittleEndianFraming() throws Exception {
        byte[] payload = RootModuleProtocol.request(ID, "runtime-start", TOKEN);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        RootModuleProtocol.writeFrame(bytes, payload);
        byte[] wire = bytes.toByteArray();
        assertEquals(payload.length & 255, wire[0] & 255);
        assertEquals(payload.length >>> 8, wire[1] & 255);
        assertArrayEquals(payload, Arrays.copyOfRange(wire, 4, wire.length));
        String json = new String(payload, StandardCharsets.UTF_8);
        assertTrue(json.contains("\"version\":1"));
        assertFalse(json.contains("arguments"));
        assertFalse(json.contains("script"));
    }

    @Test public void arbitraryOperationsAndInvalidTokensCannotBeEncoded() {
        assertThrows(IllegalArgumentException.class, () -> RootModuleProtocol.request(ID, "sh", TOKEN));
        assertThrows(IllegalArgumentException.class, () -> RootModuleProtocol.request(ID, "runtime-start; reboot", TOKEN));
        assertThrows(IllegalArgumentException.class, () -> RootModuleProtocol.request(ID, "pair", TOKEN));
        assertThrows(IllegalArgumentException.class, () -> RootModuleProtocol.request(ID, "status", "short"));
        assertThrows(IllegalArgumentException.class, () -> RootModuleProtocol.request("bad-id", "status", TOKEN));
    }

    @Test public void validReplyPreservesResultAndIdentity() throws Exception {
        JsonObject json = reply("status", "ok", 0, true);
        json.addProperty("stdout", "running\nbootMs:42\n");
        RootModuleProtocol.Reply parsed = parse(json.toString(), "status");
        assertTrue(parsed.success());
        assertEquals(ID, parsed.id);
        assertEquals("running\nbootMs:42\n", parsed.stdout);
        assertFalse(parsed.permitsLegacyFallback());
    }

    @Test public void zeroUnsignedHugeAndTruncatedFramesAreRejected() {
        for (byte[] bytes : new byte[][] {
                new byte[] {0, 0, 0, 0}, new byte[] {-1, -1, -1, -1},
                new byte[] {4, 0, 0, 0, '{'}, new byte[] {1, 0}}) {
            assertThrows(IOException.class, () -> RootModuleProtocol.readReply(new ByteArrayInputStream(bytes), ID, "status"));
        }
    }

    @Test public void invalidUtf8AndMalformedJsonAreRejected() {
        byte[] invalidUtf8 = frame(new byte[] {(byte) 0xc0, (byte) 0xaf});
        assertThrows(IOException.class, () -> RootModuleProtocol.readReply(new ByteArrayInputStream(invalidUtf8), ID, "status"));
        assertThrows(IOException.class, () -> parse("{\"version\":", "status"));
        assertThrows(IOException.class, () -> parse(reply("status", "ok", 0, true) + " {}", "status"));
    }

    @Test public void duplicateUnknownAndMissingFieldsAreRejected() {
        String valid = reply("status", "ok", 0, true).toString();
        assertThrows(IOException.class, () -> parse("{\"executed\":true," + valid.substring(1), "status"));
        JsonObject unknown = reply("status", "ok", 0, true);
        unknown.addProperty("script", "id -u");
        assertThrows(IOException.class, () -> parse(unknown.toString(), "status"));
        JsonObject missing = reply("status", "ok", 0, true);
        missing.remove("executed");
        assertThrows(IOException.class, () -> parse(missing.toString(), "status"));
    }

    @Test public void WrongIdOperationOrVersionIsRejected() {
        JsonObject wrongId = reply("status", "ok", 0, true);
        wrongId.addProperty("id", "87654321-1234-4234-8234-123456789abc");
        JsonObject wrongOperation = reply("runtime-start", "ok", 0, true);
        JsonObject wrongVersion = reply("status", "ok", 0, true);
        wrongVersion.addProperty("version", 2);
        for (JsonObject value : Arrays.asList(wrongId, wrongOperation, wrongVersion)) {
            assertThrows(IOException.class, () -> parse(value.toString(), "status"));
        }
    }

    @Test public void CoercedNumbersBooleansNullsAndOverflowAreRejected() {
        for (String field : Arrays.asList("version", "executed", "stdout")) {
            JsonObject value = reply("status", "ok", 0, true);
            value.addProperty(field, "1");
            if (field.equals("stdout")) value.add(field, null);
            assertThrows(IOException.class, () -> parse(value.toString(), "status"));
        }
        JsonObject fractional = reply("status", "ok", 0, true);
        fractional.addProperty("version", 1.0);
        assertThrows(IOException.class, () -> parse(fractional.toString(), "status"));
        String overflow = reply("status", "ok", 0, true).toString().replace("\"exitCode\":0", "\"exitCode\":2147483648");
        assertThrows(IOException.class, () -> parse(overflow, "status"));
    }

    @Test public void ContradictorySuccessAndFailureAreRejected() {
        assertThrows(IOException.class, () -> parse(reply("status", "ok", 1, false).toString(), "status"));
        assertThrows(IOException.class, () -> parse(reply("status", "busy", 0, false).toString(), "status"));
        JsonObject timeout = reply("status", "ok", 0, true);
        timeout.addProperty("timedOut", true);
        assertThrows(IOException.class, () -> parse(timeout.toString(), "status"));
    }

    @Test public void AuthorizationRequiresGrantedAndUidZeroEvidence() throws Exception {
        JsonObject authorized = reply("authorization", "ok", 0, false);
        authorized.addProperty("stdout", "0\n");
        authorized.addProperty("authorization", "granted");
        assertTrue(parse(authorized.toString(), "authorization").success());
        authorized.addProperty("authorization", "unknown");
        assertThrows(IOException.class, () -> parse(authorized.toString(), "authorization"));
        authorized.addProperty("authorization", "granted");
        authorized.addProperty("stdout", "");
        assertThrows(IOException.class, () -> parse(authorized.toString(), "authorization"));
    }

    @Test public void DeniedAndUnknownAuthorizationNeverPermitFallback() throws Exception {
        for (String code : Arrays.asList("authorization_denied", "authorization_unknown", "unauthorized")) {
            RootModuleProtocol.Reply value = parse(reply("authorization", code, 126, false).toString(), "authorization");
            assertFalse(value.success());
            assertFalse(value.permitsLegacyFallback());
        }
    }

    @Test public void ExcessiveOutputAndDuplicateCapabilitiesAreRejected() {
        JsonObject output = reply("status", "ok", 0, true);
        output.addProperty("stdout", repeat("中", 3000));
        assertThrows(IOException.class, () -> parse(output.toString(), "status"));
        JsonObject caps = reply("hello", "ok", 0, false);
        com.google.gson.JsonArray list = new com.google.gson.JsonArray();
        list.add("status"); list.add("status");
        caps.add("capabilities", list);
        assertThrows(IOException.class, () -> parse(caps.toString(), "hello"));
    }

    @Test public void OnlyExplicitUnsupportedPreExecutionResultPermitsFallback() throws Exception {
        for (String code : Arrays.asList("unsupported_operation", "incompatible_version")) {
            RootModuleProtocol.Reply value = parse(reply("runtime-start", code, 64, false).toString(), "runtime-start");
            assertTrue(value.permitsLegacyFallback());
            value.executed = true;
            assertFalse(value.permitsLegacyFallback());
            value.executed = false; value.timedOut = true;
            assertFalse(value.permitsLegacyFallback());
            value.timedOut = false; value.stdout = "a result exists";
            assertFalse(value.permitsLegacyFallback());
        }
    }

    @Test public void UnavailableConnectionReturnsNullWithoutSubmittingRequest() {
        AtomicInteger connects = new AtomicInteger();
        RootModuleTransport transport = transport(timeout -> {
            connects.incrementAndGet(); throw new IOException("absent");
        });
        assertNull(transport.request("runtime-start", TOKEN, 1000));
        assertEquals(1, connects.get());
    }

    @Test public void NonRootPeerNeverReceivesTokenAndNeverTriggersFallback() {
        FakeConnection connection = new FakeConnection(10001, new ByteArrayInputStream(new byte[0]));
        RootModuleProtocol.Reply value = transport(timeout -> connection).request("runtime-start", TOKEN, 1000);
        assertNotNull(value);
        assertEquals("module_peer_untrusted", value.code);
        assertFalse(value.permitsLegacyFallback());
        assertEquals(0, connection.writes.size());
        assertEquals(1, connection.closes.get());
    }

    @Test public void UnknownPeerCredentialsNeverReceiveToken() {
        FakeConnection connection = new FakeConnection(0, new ByteArrayInputStream(new byte[0])) {
            @Override public int peerUid() throws IOException { throw new IOException("unknown peer"); }
        };
        RootModuleProtocol.Reply value = transport(timeout -> connection).request("status", TOKEN, 1000);
        assertNotNull(value);
        assertEquals("module_peer_unverified", value.code);
        assertEquals(0, connection.writes.size());
    }

    @Test public void PartialWriteAndLostReplyAreNotReplayed() {
        FakeConnection partial = new FakeConnection(0, new ByteArrayInputStream(new byte[0])) {
            @Override public OutputStream output() {
                return new OutputStream() {
                    int count;
                    @Override public void write(int value) throws IOException {
                        if (count++ >= 2) throw new IOException("partial request");
                    }
                };
            }
        };
        for (FakeConnection connection : Arrays.asList(partial,
                new FakeConnection(0, new ByteArrayInputStream(new byte[0])))) {
            RootModuleProtocol.Reply value = transport(timeout -> connection).request("runtime-start", TOKEN, 1000);
            assertNotNull(value);
            assertEquals("module_outcome_unknown", value.code);
            assertTrue(value.executed); // Only a conservative possibility, never a running-state claim.
            assertFalse(value.permitsLegacyFallback());
        }
    }

    @Test public void VerifiedUnsupportedReplyCanSelectLegacyButBusyCannot() {
        for (String code : Arrays.asList("unsupported_operation", "busy")) {
            FakeConnection connection = new FakeConnection(0,
                    new ByteArrayInputStream(frame(reply("runtime-start", code, 64, false).toString().getBytes(StandardCharsets.UTF_8))));
            RootModuleProtocol.Reply value = transport(timeout -> connection).request("runtime-start", TOKEN, 1000);
            if (code.equals("unsupported_operation")) assertNull(value); else assertNotNull(value);
            assertTrue(connection.writes.size() > 0);
        }
    }

    @Test public void DeadlineClosesConnectionAndDoesNotSelectLegacy() {
        BlockingConnection connection = new BlockingConnection();
        long began = System.nanoTime();
        RootModuleProtocol.Reply value = transport(timeout -> connection).request("runtime-start", TOKEN, 100);
        assertNotNull(value);
        assertTrue(value.timedOut);
        assertEquals("module_timed_out", value.code);
        assertFalse(value.permitsLegacyFallback());
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began) < 1500);
        assertEquals(1, connection.closes.get());
    }

    @Test public void ExplicitCancellationClosesConnectionWithoutReplay() throws Exception {
        BlockingConnection connection = new BlockingConnection();
        RootModuleTransport transport = transport(timeout -> connection);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<RootModuleProtocol.Reply> pending = worker.submit(() -> transport.request("runtime-start", TOKEN, 5000));
            assertTrue(connection.reading.await(1, TimeUnit.SECONDS));
            transport.cancelAll();
            RootModuleProtocol.Reply value = pending.get(1, TimeUnit.SECONDS);
            assertNotNull(value);
            assertEquals("module_cancelled", value.code);
            assertFalse(value.timedOut);
            assertFalse(value.permitsLegacyFallback());
        } finally {
            worker.shutdownNow();
        }
    }

    @Rule public final TestWatcher reportedAssumptions = new TestWatcher() {
        @Override protected void skipped(AssumptionViolatedException error, Description description) {
            System.out.println("跳过 " + description.getMethodName() + ": " + error.getMessage());
        }
    };

    @Test public void pairingUidBoundsRejectInvalidAndOverflowValues() {
        for (int uid : new int[] {10000, 19999}) {
            assertTrue(RootModuleClient.pairingCommand(uid).endsWith("exec \"$BINARY\" pair --uid " + uid));
        }
        for (int uid : new int[] {9999, 20000, -1, Integer.MIN_VALUE, Integer.MAX_VALUE,
                (int) ((long) Integer.MAX_VALUE + 1)}) {
            assertThrows(IllegalArgumentException.class, () -> RootModuleClient.pairingCommand(uid));
        }
        for (String overflow : new String[] {"2147483648", "-2147483649", "4294977297"}) {
            assertThrows(NumberFormatException.class,
                    () -> RootModuleClient.pairingCommand(Integer.parseInt(overflow)));
        }
    }

    @Test public void pairingCommandIsFixedSecretFreeAndGatedBeforeExec() {
        String command = RootModuleClient.pairingCommand(10001);
        String execution = "exec \"$BINARY\" pair --uid 10001";
        assertTrue(command.startsWith("PATH=/system/bin:/system/xbin; export PATH; "));
        assertTrue(command.contains("MODDIR='/data/adb/modules/flclash_module'; "));
        assertTrue(command.contains("BINARY='/data/adb/modules/flclash_module/bin/arm64-v8a/flclashmod'; "));
        assertTrue(command.endsWith(execution));
        assertEquals(command.indexOf("exec "), command.lastIndexOf("exec "));
        assertFalse(command.contains(TOKEN));
        assertFalse(command.contains("token"));
        assertEquals(command, RootModuleClient.pairingCommand(19999)
                .replace("pair --uid 19999", "pair --uid 10001"));
        for (String gate : new String[] {
                "[ \"$(id -u)\" = 0 ]", "if ! trusted_root_directory /data; then",
                "trusted_root_directory \"$directory\" || exit 1",
                "trusted_root_file \"$BINARY\" 700 && [ -x \"$BINARY\" ]",
                "trusted_root_file \"$MODDIR/module.prop\" 600",
                "[ \"$(grep '^id=' \"$MODDIR/module.prop\")\" = id=flclash_module ]",
                "[ ! -e \"$MODDIR/disable\" ]", "[ ! -L \"$MODDIR/disable\" ]",
                "[ ! -e \"$MODDIR/remove\" ]", "[ ! -L \"$MODDIR/remove\" ]"}) {
            assertTrue("安全 gate 缺失或位于 exec 之后: " + gate,
                    command.indexOf(gate) >= 0 && command.indexOf(gate) < command.indexOf(execution));
        }
    }

    @Test public void pairingTrustedTreeExecutesOnlyFixedArgvAndStdinToken() throws Exception {
        for (boolean rootData : new boolean[] {false, true}) {
            try (PairingFixture fixture = new PairingFixture()) {
                if (rootData) {
                    fixture.environment.put("TEST_DATA_ROOT", "1");
                }
                ShellReply result = fixture.pair();
                assertEquals(result.output, 0, result.exitCode);
                assertEquals("pair --uid 10001\n", fixture.read(fixture.events));
                assertEquals("3\npair\n--uid\n10001\n", fixture.read(fixture.argv));
                assertEquals(TOKEN + "\n", fixture.read(fixture.tokenInput));
            }
        }
    }

    @Test public void pairingRejectsNonRootAndWritableAncestorsBeforeExec() throws Exception {
        for (String name : new String[] {"root", "adb", "modules", "module", "bin", "arch"}) {
            for (String[] bad : new String[][] {{"%u", "10000"}, {"%a", "770"}, {"%a", "702"}}) {
                try (PairingFixture fixture = new PairingFixture()) {
                    fixture.badMetadata(name, bad[0], bad[1]);
                    fixture.assertRejected(name + " " + Arrays.toString(bad));
                }
            }
        }
    }

    @Test public void pairingDataExceptionRequiresExactOwnerGroupModeAndNoSpecialBits() throws Exception {
        for (String[] bad : new String[][] {
                {"%u", "0"}, {"%u", "1001"}, {"%u", "10000"}, {"%g", "1001"},
                {"%a", "700"}, {"%a", "770"}, {"%a", "777"}, {"%a", "0771"},
                {"%a", "1771"}, {"%a", "2771"}, {"%a", "4771"}}) {
            try (PairingFixture fixture = new PairingFixture()) {
                fixture.badMetadata("data", bad[0], bad[1]);
                fixture.assertRejected("/data " + Arrays.toString(bad));
            }
        }
    }

    @Test public void pairingStatErrorsAndMalformedModesFailClosedBeforeExec() throws Exception {
        for (String name : new String[] {"root", "data", "adb", "modules", "module", "bin", "arch", "binary", "marker"}) {
            String[] fields = name.equals("data") ? new String[] {"%u", "%g", "%a"}
                    : name.equals("binary") || name.equals("marker") ? new String[] {"%u", "%a", "%h"}
                    : new String[] {"%u", "%a"};
            for (String field : fields) {
                try (PairingFixture fixture = new PairingFixture()) {
                    fixture.badMetadata(name, field, "error");
                    fixture.assertRejected(name + " stat " + field + " 失败");
                }
            }
        }
        for (String mode : new String[] {"", "not-a-mode", "888", "77777", "7 00"}) {
            try (PairingFixture fixture = new PairingFixture()) {
                fixture.badMetadata("adb", "%a", mode);
                fixture.assertRejected("畸形目录 mode: " + mode);
            }
        }
    }

    @Test public void pairingRejectsUntrustedBinaryAndMarkerMetadataBeforeExec() throws Exception {
        for (String name : new String[] {"binary", "marker"}) {
            String[] modes = name.equals("binary") ? new String[] {"600", "755", "770", "1700", "0700"}
                    : new String[] {"640", "644", "700", "1600", "0600"};
            try (PairingFixture fixture = new PairingFixture()) {
                fixture.badMetadata(name, "%u", "10000");
                fixture.assertRejected(name + " 不属于 Root");
            }
            for (String mode : modes) {
                try (PairingFixture fixture = new PairingFixture()) {
                    fixture.badMetadata(name, "%a", mode);
                    fixture.assertRejected(name + " 错误 mode: " + mode);
                }
            }
        }
    }

    @Test public void pairingRejectsRealHardlinkedBinaryAndMarkerBeforeExec() throws Exception {
        for (String name : new String[] {"binary", "marker"}) {
            try (PairingFixture fixture = new PairingFixture()) {
                Files.createLink(fixture.temporary.resolve("second-link"), fixture.path(name));
                ShellReply links = fixture.shell("stat -c %h \"$TEST_" + name.toUpperCase(Locale.ROOT) + "\"", new byte[0]);
                assertEquals(links.output, 0, links.exitCode);
                assertEquals("2", links.output.trim());
                fixture.assertRejected(name + " 真实 nlink=2");
            }
        }
    }

    @Test public void pairingRejectsMissingAndNonRegularFilesBeforeExec() throws Exception {
        for (String name : new String[] {"binary", "marker"}) {
            for (boolean directory : new boolean[] {false, true}) {
                try (PairingFixture fixture = new PairingFixture()) {
                    Files.delete(fixture.path(name));
                    if (directory) Files.createDirectory(fixture.path(name));
                    fixture.assertRejected(name + (directory ? " 是目录" : " 不存在"));
                }
            }
        }
    }

    @Test public void pairingRejectsWrongMissingAndDuplicateModuleIdsBeforeExec() throws Exception {
        for (String marker : new String[] {"", "id=unrelated\n", "id=flclash_module_extra\n",
                "id=flclash_module\nid=flclash_module\n", "id=flclash_module\nid=unrelated\n"}) {
            try (PairingFixture fixture = new PairingFixture()) {
                Files.write(fixture.path("marker"), marker.getBytes(StandardCharsets.US_ASCII));
                fixture.assertRejected("不准确或重复的 module id");
            }
        }
    }

    @Test public void pairingRejectsDisableAndRemoveFilesAndDirectoriesBeforeExec() throws Exception {
        for (String flag : new String[] {"disable", "remove"}) {
            for (boolean directory : new boolean[] {false, true}) {
                try (PairingFixture fixture = new PairingFixture()) {
                    Path path = fixture.path("module").resolve(flag);
                    if (directory) Files.createDirectory(path); else Files.createFile(path);
                    fixture.assertRejected(flag + (directory ? " 目录" : " 文件"));
                }
            }
        }
    }

    @Test public void pairingNonRootOrUnknownCallerNeverExecutes() throws Exception {
        for (String uid : new String[] {"1000", "10001", "20000", "error"}) {
            try (PairingFixture fixture = new PairingFixture()) {
                fixture.environment.put("TEST_CALLER_UID", uid);
                fixture.assertRejected("非 Root 或 id 失败: " + uid);
            }
        }
    }

    @Test public void pairingRejectsRealSymlinkedDirectoriesBeforeExec() throws Exception {
        for (String name : new String[] {"root", "data", "adb", "modules", "module", "bin", "arch"}) {
            try (PairingFixture fixture = new PairingFixture()) {
                Path original = fixture.path(name);
                Path target = original.resolveSibling(original.getFileName() + "-real");
                Files.move(original, target);
                fixture.symlink(original, target);
                fixture.assertRejected(name + " 真实目录符号链接");
            }
        }
    }

    @Test public void pairingRejectsRealSymlinkedBinaryAndMarkerBeforeExec() throws Exception {
        for (String name : new String[] {"binary", "marker"}) {
            try (PairingFixture fixture = new PairingFixture()) {
                Path original = fixture.path(name);
                Path target = original.resolveSibling(original.getFileName() + "-real");
                Files.move(original, target);
                fixture.symlink(original, target);
                fixture.assertRejected(name + " 真实文件符号链接");
            }
        }
    }

    @Test public void pairingRejectsDanglingDisableAndRemoveSymlinksBeforeExec() throws Exception {
        for (String flag : new String[] {"disable", "remove"}) {
            try (PairingFixture fixture = new PairingFixture()) {
                Path path = fixture.path("module").resolve(flag);
                fixture.symlink(path, fixture.temporary.resolve("absent-target"));
                assertFalse(Files.exists(path));
                fixture.assertRejected(flag + " dangling symlink");
            }
        }
    }

    @Test public void pairingRejectsNonExecutableBinaryBeforeExecWhereHostSupportsIt() throws Exception {
        try (PairingFixture fixture = new PairingFixture()) {
            ShellReply changed = fixture.shell("chmod 600 \"$TEST_BINARY\" && [ ! -x \"$TEST_BINARY\" ]", new byte[0]);
            Assume.assumeTrue("宿主文件系统无法让普通 shell 文件失去执行权限；未验证真实 -x 拒绝", changed.exitCode == 0);
            fixture.assertRejected("真实不可执行 binary，模拟 metadata 仍为 700");
        }
    }

    private static final class ShellReply {
        final int exitCode;
        final String output;
        ShellReply(int exitCode, String output) { this.exitCode = exitCode; this.output = output; }
    }

    private static final class PairingFixture implements AutoCloseable {
        // 仅模拟 Android UID/mode；文件类型、符号链接、执行位与 nlink 由真实宿主文件系统判断。
        private static final String METADATA =
                "HOST_STAT=$(command -v stat) || exit 2; HOST_GREP=$(command -v grep) || exit 2;\n"
                + "id() { [ \"$1\" = -u ] || return 2; [ \"$TEST_CALLER_UID\" != error ] || return 1; printf '%s\\n' \"$TEST_CALLER_UID\"; }\n"
                + "grep() { \"$HOST_GREP\" \"$@\"; }\n"
                + "stat() { [ \"$1\" = -c ] || return 2; stat_format=$2; stat_path=$3;\n"
                + "if [ \"$stat_path\" = \"$TEST_BAD_PATH\" ] && [ \"$stat_format\" = \"$TEST_BAD_FIELD\" ]; then\n"
                + "[ \"$TEST_BAD_VALUE\" != error ] || return 1; printf '%s\\n' \"$TEST_BAD_VALUE\"; return 0; fi;\n"
                + "case \"$stat_format\" in %u|%g)\n"
                + "if [ \"$stat_path\" = \"$TEST_DATA\" ] && [ \"$TEST_DATA_ROOT\" != 1 ]; then printf '1000\\n'; else printf '0\\n'; fi ;;\n"
                + "%a) if [ \"$stat_path\" = \"$TEST_DATA\" ] && [ \"$TEST_DATA_ROOT\" != 1 ]; then printf '771\\n';\n"
                + "elif [ \"$stat_path\" = \"$TEST_MARKER\" ]; then printf '600\\n'; else printf '700\\n'; fi ;;\n"
                + "%h) \"$HOST_STAT\" \"$@\" ;; *) return 2 ;; esac; }\n";
        final Path temporary;
        final Path events;
        final Path argv;
        final Path tokenInput;
        final Map<String, Path> paths = new HashMap<>();
        final Map<String, String> environment = new HashMap<>();

        PairingFixture() throws Exception {
            ShellReply tools = shell("command -v stat >/dev/null && command -v grep >/dev/null && command -v chmod >/dev/null", new byte[0]);
            Assume.assumeTrue("动态回归需要可用宿主 POSIX shell 和 stat/grep/chmod", tools.exitCode == 0);
            Path build = Paths.get(System.getProperty("rootModuleTest.buildDir", "build")).toAbsolutePath();
            assertTrue("必须指定已存在的项目 build 父目录: " + build, Files.isDirectory(build));
            temporary = Files.createTempDirectory(build, "root-pairing-");
            events = temporary.resolve("cli-events");
            argv = temporary.resolve("cli-argv");
            tokenInput = temporary.resolve("cli-stdin");
            paths.put("root", temporary.resolve("root"));
            paths.put("data", path("root").resolve("data"));
            paths.put("adb", path("data").resolve("adb"));
            paths.put("modules", path("adb").resolve("modules"));
            paths.put("module", path("modules").resolve("flclash_module"));
            paths.put("bin", path("module").resolve("bin"));
            paths.put("arch", path("bin").resolve("arm64-v8a"));
            paths.put("binary", path("arch").resolve("flclashmod"));
            paths.put("marker", path("module").resolve("module.prop"));
            Files.createDirectories(path("arch"));
            Files.write(path("marker"), "id=flclash_module\n".getBytes(StandardCharsets.US_ASCII));
            Files.write(path("binary"), ("#!/bin/sh\n"
                    + "printf '%s\\n' \"$*\" > \"$TEST_EVENTS\"\n"
                    + "printf '%s\\n' \"$#\" \"$1\" \"$2\" \"$3\" > \"$TEST_ARGV\"\n"
                    + "IFS= read -r received || exit 2\n"
                    + "printf '%s\\n' \"$received\" > \"$TEST_INPUT\"\n").getBytes(StandardCharsets.US_ASCII));
            for (Map.Entry<String, Path> entry : paths.entrySet()) {
                environment.put("TEST_" + entry.getKey().toUpperCase(Locale.ROOT), shellPath(entry.getValue()));
            }
            environment.put("TEST_TEMP", shellPath(temporary));
            environment.put("TEST_EVENTS", shellPath(events));
            environment.put("TEST_ARGV", shellPath(argv));
            environment.put("TEST_INPUT", shellPath(tokenInput));
            environment.put("TEST_CALLER_UID", "0");
            environment.put("TEST_DATA_ROOT", "0");
            environment.put("TEST_BAD_PATH", "");
            environment.put("TEST_BAD_FIELD", "");
            environment.put("TEST_BAD_VALUE", "");
            ShellReply setup = shell("chmod 700 \"$TEST_TEMP\" \"$TEST_BINARY\"", new byte[0]);
            assertEquals(setup.output, 0, setup.exitCode);
            assertTrue(Files.isRegularFile(path("binary"), LinkOption.NOFOLLOW_LINKS));
        }

        Path path(String name) { return paths.get(name); }
        String read(Path file) throws IOException { return new String(Files.readAllBytes(file), StandardCharsets.US_ASCII); }

        void badMetadata(String name, String field, String value) {
            environment.put("TEST_BAD_PATH", shellPath(path(name)));
            environment.put("TEST_BAD_FIELD", field);
            environment.put("TEST_BAD_VALUE", value);
        }

        ShellReply pair() throws Exception {
            // 只映射原命令中的固定 Android 路径，不重写任何安全判断，PATH 仍保持生产值。
            String command = RootModuleClient.pairingCommand(10001)
                    .replace("'/data/adb/modules/flclash_module/bin/arm64-v8a/flclashmod'", "\"$TEST_BINARY\"")
                    .replace("'/data/adb/modules/flclash_module'", "\"$TEST_MODULE\"")
                    .replace("/data/adb/modules", "\"$TEST_MODULES\"")
                    .replace("/data/adb", "\"$TEST_ADB\"")
                    .replace("/data", "\"$TEST_DATA\"")
                    .replace("for directory in / ", "for directory in \"$TEST_ROOT\" ");
            assertFalse("残留真实 Android 路径", command.contains("/data"));
            assertFalse("残留真实根目录 gate", command.contains("for directory in / "));
            assertTrue(command.startsWith("PATH=/system/bin:/system/xbin; export PATH; "));
            assertTrue(command.endsWith("exec \"$BINARY\" pair --uid 10001"));
            assertFalse(command.contains(TOKEN));
            Path script = temporary.resolve("pair-command.sh");
            Files.write(script, (METADATA + command + "\n").getBytes(StandardCharsets.UTF_8));
            return execute(new ProcessBuilder(System.getProperty("rootModuleTest.shell", "sh"), shellPath(script)),
                    (TOKEN + "\n").getBytes(StandardCharsets.US_ASCII));
        }

        void assertRejected(String scenario) throws Exception {
            ShellReply result = pair();
            assertEquals(scenario + ": 必须由安全 gate 拒绝，而非解析或 exec 失败: " + result.output, 1, result.exitCode);
            assertFalse(scenario + " 在拒绝前调用了 CLI", Files.exists(events, LinkOption.NOFOLLOW_LINKS));
            assertFalse(scenario + " 泄露了 argv", Files.exists(argv, LinkOption.NOFOLLOW_LINKS));
            assertFalse(scenario + " 将 token 送达了 CLI", Files.exists(tokenInput, LinkOption.NOFOLLOW_LINKS));
        }

        void symlink(Path link, Path target) throws Exception {
            try {
                Files.createSymbolicLink(link, target);
            } catch (IOException | UnsupportedOperationException error) {
                Assume.assumeNoException("宿主无法创建真实符号链接；相应场景未验证", error);
            }
            assertTrue("必须是真实符号链接，不能使用复制替代", Files.isSymbolicLink(link));
            environment.put("TEST_LINK", shellPath(link));
            ShellReply recognized = shell("[ -L \"$TEST_LINK\" ]", new byte[0]);
            Assume.assumeTrue("宿主 POSIX shell 不识别真实符号链接；相应场景未验证", recognized.exitCode == 0);
        }

        ShellReply shell(String source, byte[] stdin) throws Exception {
            return execute(new ProcessBuilder(System.getProperty("rootModuleTest.shell", "sh"), "-c", source), stdin);
        }

        ShellReply execute(ProcessBuilder builder, byte[] stdin) throws Exception {
            builder.environment().putAll(environment);
            builder.redirectErrorStream(true);
            Process process;
            try {
                process = builder.start();
            } catch (IOException error) {
                Assume.assumeNoException("缺少可用宿主 POSIX shell；动态场景未验证", error);
                throw error;
            }
            try {
                try (OutputStream input = process.getOutputStream()) { input.write(stdin); }
                boolean ended = process.waitFor(10, TimeUnit.SECONDS);
                assertTrue("宿主隔离回归超过执行期限", ended);
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                try (InputStream stream = process.getInputStream()) {
                    byte[] buffer = new byte[1024];
                    int count;
                    while ((count = stream.read(buffer)) >= 0) output.write(buffer, 0, count);
                }
                return new ShellReply(process.exitValue(), new String(output.toByteArray(), StandardCharsets.UTF_8));
            } finally {
                if (process.isAlive()) process.destroyForcibly();
            }
        }

        private static String shellPath(Path path) {
            String value = path.toAbsolutePath().toString().replace('\\', '/');
            return value.length() > 2 && value.charAt(1) == ':'
                    ? "/" + Character.toLowerCase(value.charAt(0)) + value.substring(2) : value;
        }

        @Override public void close() throws IOException {
            List<Path> entries = new ArrayList<>();
            try (Stream<Path> walk = Files.walk(temporary)) {
                walk.sorted(Comparator.reverseOrder()).forEach(entries::add);
            }
            for (Path entry : entries) Files.delete(entry);
        }
    }

    private static JsonObject reply(String operation, String code, int exitCode, boolean executed) {
        JsonObject json = new JsonObject();
        json.addProperty("version", 1); json.addProperty("id", ID); json.addProperty("operation", operation);
        json.addProperty("code", code); json.addProperty("exitCode", exitCode);
        json.addProperty("stdout", ""); json.addProperty("stderr", "");
        json.addProperty("timedOut", false); json.addProperty("executed", executed);
        return json;
    }

    private static RootModuleProtocol.Reply parse(String json, String operation) throws IOException {
        return RootModuleProtocol.readReply(new ByteArrayInputStream(frame(json.getBytes(StandardCharsets.UTF_8))), ID, operation);
    }

    private static byte[] frame(byte[] payload) {
        byte[] wire = new byte[payload.length + 4];
        wire[0] = (byte) payload.length; wire[1] = (byte) (payload.length >>> 8);
        wire[2] = (byte) (payload.length >>> 16); wire[3] = (byte) (payload.length >>> 24);
        System.arraycopy(payload, 0, wire, 4, payload.length);
        return wire;
    }

    private static RootModuleTransport transport(RootModuleTransport.Connector connector) {
        return new RootModuleTransport(connector, () -> ID);
    }

    private static String repeat(String text, int count) {
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < count; i++) value.append(text);
        return value.toString();
    }

    private static class FakeConnection implements RootModuleTransport.Connection {
        final int uid;
        final InputStream input;
        final ByteArrayOutputStream writes = new ByteArrayOutputStream();
        final AtomicInteger closes = new AtomicInteger();
        FakeConnection(int uid, InputStream input) { this.uid = uid; this.input = input; }
        @Override public int peerUid() throws IOException { return uid; }
        @Override public InputStream input() { return input; }
        @Override public OutputStream output() { return writes; }
        @Override public void close() { closes.incrementAndGet(); }
    }

    private static final class BlockingConnection extends FakeConnection {
        final CountDownLatch reading = new CountDownLatch(1);
        final CountDownLatch closed = new CountDownLatch(1);
        BlockingConnection() { super(0, new ByteArrayInputStream(new byte[0])); }
        @Override public InputStream input() {
            return new InputStream() {
                @Override public int read() throws IOException {
                    reading.countDown();
                    try { closed.await(); } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
                    throw new IOException("closed");
                }
            };
        }
        @Override public void close() { super.close(); closed.countDown(); }
    }
}
