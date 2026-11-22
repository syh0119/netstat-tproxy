package com.follow.clash.root;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/** Portable, bounded transport; Android's LocalSocket adapter is in RootModuleClient. */
public final class RootModuleTransport {
    public interface Connection extends AutoCloseable {
        int peerUid() throws IOException;
        InputStream input() throws IOException;
        OutputStream output() throws IOException;
        default void setIoTimeout(int timeoutMillis) throws IOException { }
        @Override void close() throws IOException;
    }

    public interface Connector {
        Connection connect(int timeoutMillis) throws IOException;
    }

    private static final ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "flclash-module-deadline");
        thread.setDaemon(true);
        return thread;
    });
    private final Connector connector;
    private final Supplier<String> ids;
    private final Set<Call> active = Collections.newSetFromMap(new ConcurrentHashMap<Call, Boolean>());

    public RootModuleTransport(Connector connector) {
        this(connector, () -> UUID.randomUUID().toString());
    }

    RootModuleTransport(Connector connector, Supplier<String> ids) {
        this.connector = connector;
        this.ids = ids;
    }

    /** Opens and authenticates the server without sending a token or any operation. */
    public boolean trustedServerAvailable(int timeoutMillis) throws IOException {
        Connection connection;
        try {
            connection = connector.connect(timeoutMillis);
        } catch (IOException unavailable) {
            return false;
        }
        try {
            if (connection.peerUid() != 0) throw new SecurityException("Module server is not UID 0");
            return true;
        } finally {
            closeQuietly(connection);
        }
    }

    /**
     * null is narrowly defined: no request was sent, or the verified server explicitly
     * rejected an unsupported operation/version before execution. No other error is retried.
     */
    public RootModuleProtocol.Reply request(String operation, String token, int timeoutMillis) {
        if (timeoutMillis < 1 || timeoutMillis > 20000) throw new IllegalArgumentException("Invalid module deadline");
        long began = System.nanoTime();
        String id = ids.get();
        byte[] payload = RootModuleProtocol.request(id, operation, token);
        Call call = new Call();
        active.add(call);
        ScheduledFuture<?> deadline = DEADLINES.schedule(() -> call.cancel("timeout"), timeoutMillis, TimeUnit.MILLISECONDS);
        boolean verifyingPeer = false;
        try {
            Connection connection = connector.connect(Math.min(timeoutMillis, 250));
            call.connection.set(connection);
            if (call.reason.get() != null) return interrupted(id, operation, call);
            verifyingPeer = true;
            if (connection.peerUid() != 0) {
                return RootModuleProtocol.Reply.failure(id, operation, "module_peer_untrusted",
                        "Module peer was not UID 0; request was not sent", false, false);
            }
            if (call.reason.get() != null) return interrupted(id, operation, call);
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began);
            connection.setIoTimeout((int) Math.max(1, timeoutMillis - elapsedMillis));
            // Set before the first write. Even a partial write/EOF must not trigger a
            // second start via su: the caller cannot prove what the server received.
            call.mightHaveSent.set(true);
            RootModuleProtocol.writeFrame(connection.output(), payload);
            RootModuleProtocol.Reply reply = RootModuleProtocol.readReply(connection.input(), id, operation);
            if (call.reason.get() != null) return interrupted(id, operation, call);
            return reply.permitsLegacyFallback() ? null : reply;
        } catch (IOException error) {
            if (call.reason.get() != null) return interrupted(id, operation, call);
            if (!verifyingPeer && !call.mightHaveSent.get()) return null;
            return RootModuleProtocol.Reply.failure(id, operation,
                    call.mightHaveSent.get() ? "module_outcome_unknown" : "module_peer_unverified",
                    "Module response could not be verified (" + error.getClass().getSimpleName() + ")",
                    false, call.mightHaveSent.get());
        } catch (RuntimeException error) {
            return RootModuleProtocol.Reply.failure(id, operation, "module_transport_failed",
                    "Module transport failed (" + error.getClass().getSimpleName() + ")",
                    false, call.mightHaveSent.get());
        } finally {
            deadline.cancel(false);
            closeQuietly(call.connection.getAndSet(null));
            active.remove(call);
        }
    }

    public void cancelAll() {
        for (Call call : active) call.cancel("cancelled");
    }

    private static RootModuleProtocol.Reply interrupted(String id, String operation, Call call) {
        boolean timedOut = "timeout".equals(call.reason.get());
        return RootModuleProtocol.Reply.failure(id, operation,
                timedOut ? "module_timed_out" : "module_cancelled",
                "Module request " + (timedOut ? "exceeded its deadline" : "was cancelled")
                        + "; do not replay a privileged action", timedOut, call.mightHaveSent.get());
    }

    private static void closeQuietly(Connection connection) {
        if (connection == null) return;
        try { connection.close(); } catch (IOException | RuntimeException ignored) { }
    }

    private static final class Call {
        final AtomicReference<Connection> connection = new AtomicReference<>();
        final AtomicReference<String> reason = new AtomicReference<>();
        final AtomicBoolean mightHaveSent = new AtomicBoolean();

        void cancel(String why) {
            if (reason.compareAndSet(null, why)) closeQuietly(connection.getAndSet(null));
        }
    }
}
