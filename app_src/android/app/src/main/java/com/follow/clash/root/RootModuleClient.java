package com.follow.clash.root;

import android.content.Context;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.AtomicFile;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Optional Magisk control plane. No VPN/TUN or network rules are owned by this client. */
public final class RootModuleClient {
    public interface Bootstrap {
        boolean run(String fixedCommand, byte[] tokenInput);
    }

    private static final String PACKAGE = "com.follow.clash.root";
    private static final String MODULE = "/data/adb/modules/flclash_module";
    private static final String BINARY = MODULE + "/bin/arm64-v8a/flclashmod";
    private static final ThreadPoolExecutor CONNECTORS = new ThreadPoolExecutor(
            0, 4, 30, TimeUnit.SECONDS, new SynchronousQueue<Runnable>(), task -> {
                Thread thread = new Thread(task, "flclash-module-connect");
                thread.setDaemon(true);
                return thread;
            });
    private final int uid;
    private final String packageName;
    private final AtomicFile credentials;
    private final RootModuleTransport transport;
    private volatile String token;
    private volatile boolean invalidStorage;

    public RootModuleClient(Context context) {
        uid = context.getApplicationInfo().uid;
        packageName = context.getPackageName();
        credentials = new AtomicFile(new File(context.getNoBackupFilesDir(), "root-module.token"));
        transport = new RootModuleTransport(RootModuleClient::connectLocalSocket);
        try {
            readCredentials();
        } catch (IOException error) {
            invalidStorage = true;
        }
    }

    private static RootModuleTransport.Connection connectLocalSocket(int timeoutMillis) throws IOException {
        LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_STREAM);
        Future<?> connecting = null;
        boolean connected = false;
        try {
            // Android exposes connect(endpoint, timeout), but its implementation throws
            // UnsupportedOperationException. Create the fd first so cancellation can close
            // it without waiting for connect's outer monitor, and bound the real connect.
            socket.getInputStream();
            socket.setSoTimeout(timeoutMillis);
            connecting = CONNECTORS.submit(() -> {
                socket.connect(new LocalSocketAddress(RootModuleProtocol.SOCKET_NAME,
                        LocalSocketAddress.Namespace.ABSTRACT));
                return null;
            });
            connecting.get(timeoutMillis, TimeUnit.MILLISECONDS);
            connected = true;
            return new RootModuleTransport.Connection() {
                @Override public int peerUid() throws IOException { return socket.getPeerCredentials().getUid(); }
                @Override public InputStream input() throws IOException { return socket.getInputStream(); }
                @Override public OutputStream output() throws IOException { return socket.getOutputStream(); }
                @Override public void setIoTimeout(int timeout) throws IOException { socket.setSoTimeout(timeout); }
                @Override public void close() throws IOException { socket.close(); }
            };
        } catch (TimeoutException error) {
            throw new IOException("Module connection deadline exceeded", error);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("Module connection interrupted", error);
        } catch (ExecutionException | RejectedExecutionException error) {
            throw new IOException("Module connection unavailable", error);
        } finally {
            if (!connected) {
                try { socket.close(); } catch (IOException ignored) { }
                if (connecting != null) connecting.cancel(true);
            }
        }
    }

    /** Must only be called from an explicit start after normal Magisk authorization. */
    public synchronized boolean prepare(Bootstrap bootstrap) throws IOException {
        // Version 1 intentionally supports the primary user and ordinary application UIDs.
        if (!PACKAGE.equals(packageName) || uid < 10000 || uid >= 20000) return false;
        if (!transport.trustedServerAvailable(250)) return false;
        if (invalidStorage) throw new IOException("Module credential storage failed verification");
        if (token != null) {
            RootModuleProtocol.Reply hello = transport.request("hello", token, 4000);
            if (hello == null) return false;
            if (hello.success()) {
                requireCapabilities(hello);
                return true;
            }
            if (!"unauthorized".equals(hello.code) || hello.executed || hello.timedOut) {
                throw new IOException("Module handshake failed: " + hello.code);
            }
        } else {
            token = randomToken();
            saveCredentials(token);
        }
        // Bootstrap exposes only the fixed enrollment CLI. The secret is passed on stdin,
        // not in argv, and is never added to RootShell's diagnostic log.
        String command = pairingCommand(uid);
        if (!bootstrap.run(command, (token + "\n").getBytes(StandardCharsets.US_ASCII))) {
            throw new IOException("Module pairing was not confirmed; no control action was submitted");
        }
        RootModuleProtocol.Reply hello = transport.request("hello", token, 4000);
        if (hello == null || !hello.success()) throw new IOException("Paired module handshake was not confirmed");
        requireCapabilities(hello);
        return true;
    }

    /** Fixed Root-only enrollment CLI; no caller-supplied path, arguments or secret in argv. */
    static String pairingCommand(int uid) {
        if (uid < 10000 || uid >= 20000) {
            throw new IllegalArgumentException("Only primary-user application UIDs can pair");
        }
        // The executable cannot validate its own path until after exec. Check the entire
        // fixed directory chain first, with the same narrow /data exception as the daemon.
        return "PATH=/system/bin:/system/xbin; export PATH; "
                + "MODDIR='" + MODULE + "'; BINARY='" + BINARY + "'; "
                + "trusted_root_directory() { "
                + "[ ! -L \"$1\" ] && [ -d \"$1\" ] && [ \"$(stat -c %u \"$1\")\" = 0 ] || return 1; "
                + "mode=$(stat -c %a \"$1\") || return 1; "
                + "case \"$mode\" in ''|*[!0-7]*) return 1 ;; esac; "
                + "[ \"${#mode}\" -le 4 ] && [ \"$((0$mode & 0022))\" -eq 0 ]; }; "
                + "trusted_root_file() { "
                + "[ ! -L \"$1\" ] && [ -f \"$1\" ] && [ \"$(stat -c %u \"$1\")\" = 0 ] && "
                + "[ \"$(stat -c %a \"$1\")\" = \"$2\" ] && [ \"$(stat -c %h \"$1\")\" = 1 ]; }; "
                + "[ \"$(id -u)\" = 0 ] && [ ! -L /data ] && [ -d /data ] || exit 1; "
                + "if ! trusted_root_directory /data; then "
                + "[ \"$(stat -c %u /data)\" = 1000 ] && [ \"$(stat -c %g /data)\" = 1000 ] && "
                + "[ \"$(stat -c %a /data)\" = 771 ] || exit 1; fi; "
                + "for directory in / /data/adb /data/adb/modules \"$MODDIR\" \"$MODDIR/bin\" \"$MODDIR/bin/arm64-v8a\"; do "
                + "trusted_root_directory \"$directory\" || exit 1; done; "
                + "trusted_root_file \"$BINARY\" 700 && [ -x \"$BINARY\" ] && "
                + "trusted_root_file \"$MODDIR/module.prop\" 600 && "
                + "[ \"$(grep '^id=' \"$MODDIR/module.prop\")\" = id=flclash_module ] || exit 1; "
                + "[ ! -e \"$MODDIR/disable\" ] && [ ! -L \"$MODDIR/disable\" ] && "
                + "[ ! -e \"$MODDIR/remove\" ] && [ ! -L \"$MODDIR/remove\" ] || exit 1; "
                + "exec \"$BINARY\" pair --uid " + uid;
    }

    public RootModuleProtocol.Reply request(String operation, int timeoutMillis) {
        if (invalidStorage) {
            return RootModuleProtocol.Reply.failure("", operation, "module_credentials_invalid",
                    "Module credential storage failed verification", false, false);
        }
        String currentToken = token;
        if (currentToken == null) return null; // Never enroll or trigger a Root prompt in the background.
        return transport.request(operation, currentToken, timeoutMillis);
    }

    public void cancel() {
        transport.cancelAll();
    }

    private static void requireCapabilities(RootModuleProtocol.Reply hello) throws IOException {
        if (!hello.capabilities.containsAll(RootModuleProtocol.OPERATIONS)) {
            throw new IOException("Module does not provide the required version 1 capabilities");
        }
    }

    private void readCredentials() throws IOException {
        File base = credentials.getBaseFile();
        boolean exists = privateFile(base, true);
        boolean backupExists = privateFile(new File(base.getPath() + ".bak"), true);
        if (!exists && !backupExists) return;
        try (FileInputStream input = credentials.openRead()) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[66];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (output.size() + count > 65) throw new IOException("Invalid module credential size");
                output.write(buffer, 0, count);
            }
            byte[] bytes = output.toByteArray();
            if (bytes.length != 65 || bytes[64] != '\n') throw new IOException("Invalid module credential format");
            String value = new String(bytes, 0, 64, StandardCharsets.US_ASCII);
            if (!RootModuleProtocol.validToken(value)) throw new IOException("Invalid module credential token");
            token = value;
        }
    }

    private void saveCredentials(String value) throws IOException {
        File base = credentials.getBaseFile();
        privateFile(base, true);
        privateFile(new File(base.getPath() + ".bak"), true);
        privateFile(new File(base.getPath() + ".new"), true);
        FileOutputStream output = credentials.startWrite();
        try {
            Os.fchmod(output.getFD(), 0600);
            output.write((value + "\n").getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
            credentials.finishWrite(output);
            privateFile(base, false);
        } catch (IOException | ErrnoException error) {
            credentials.failWrite(output);
            invalidStorage = true;
            throw new IOException("Could not persist private module credentials", error);
        }
    }

    private static boolean privateFile(File file, boolean absentAllowed) throws IOException {
        try {
            StructStat stat = Os.lstat(file.getPath());
            if (stat.st_uid != Process.myUid() || stat.st_nlink != 1
                    || (stat.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG
                    || (stat.st_mode & 0077) != 0) {
                throw new IOException("Module credentials are not a private owned regular file");
            }
            return true;
        } catch (ErrnoException error) {
            if (absentAllowed && error.errno == OsConstants.ENOENT) return false;
            throw new IOException("Module credentials could not be inspected", error);
        }
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        char[] result = new char[64];
        char[] hex = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            result[i * 2] = hex[(bytes[i] & 255) >>> 4];
            result[i * 2 + 1] = hex[bytes[i] & 15];
        }
        return new String(result);
    }
}
