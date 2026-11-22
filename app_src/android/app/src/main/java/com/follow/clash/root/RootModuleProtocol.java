package com.follow.clash.root;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Fixed-operation control protocol. This is not the mihomo core RPC protocol. */
public final class RootModuleProtocol {
    public static final int VERSION = 1;
    public static final int MAX_REQUEST_FRAME = 4096;
    public static final int MAX_RESPONSE_FRAME = 128 * 1024;
    public static final int MAX_OUTPUT = 8192;
    public static final String SOCKET_NAME = "flclash.module.v1";
    private static final Pattern ID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern TOKEN = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern INTEGER = Pattern.compile("-?(0|[1-9][0-9]*)");
    public static final Set<String> OPERATIONS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "hello", "authorization", "status", "vpn-options", "runtime-identity", "validate",
            "validation-log", "runtime-settings", "runtime-start")));
    private static final Set<String> REQUIRED = new HashSet<>(Arrays.asList(
            "version", "id", "operation", "code", "exitCode", "stdout", "stderr", "timedOut", "executed"));
    private static final Set<String> AUTHORIZATION_STATES = new HashSet<>(Arrays.asList(
            "granted", "denied", "unknown"));

    private RootModuleProtocol() {}

    public static boolean validToken(String token) {
        return token != null && TOKEN.matcher(token).matches();
    }

    public static byte[] request(String id, String operation, String token) {
        if (!ID.matcher(id).matches() || !OPERATIONS.contains(operation) || !validToken(token)) {
            throw new IllegalArgumentException("Invalid fixed module request");
        }
        // All interpolated values are restricted ASCII identifiers; there are no arguments,
        // file paths, scripts, environment variables or arbitrary strings in this protocol.
        return ("{\"version\":1,\"id\":\"" + id + "\",\"operation\":\"" + operation
                + "\",\"token\":\"" + token + "\"}").getBytes(StandardCharsets.UTF_8);
    }

    public static void writeFrame(OutputStream output, byte[] payload) throws IOException {
        if (payload.length == 0 || payload.length > MAX_REQUEST_FRAME) {
            throw new IOException("Module request exceeds frame limit");
        }
        output.write(new byte[] {
                (byte) payload.length, (byte) (payload.length >>> 8),
                (byte) (payload.length >>> 16), (byte) (payload.length >>> 24)});
        output.write(payload);
        // LocalSocket writes are unbuffered. Its flush() waits for the peer to drain
        // the socket and is not a delivery acknowledgement; do not block on it.
    }

    public static Reply readReply(InputStream input, String id, String operation) throws IOException {
        byte[] header = readExactly(input, 4);
        long length = (header[0] & 255L) | ((header[1] & 255L) << 8)
                | ((header[2] & 255L) << 16) | ((header[3] & 255L) << 24);
        if (length == 0 || length > MAX_RESPONSE_FRAME) {
            throw new IOException("Module response exceeds frame limit");
        }
        byte[] payload = readExactly(input, (int) length);
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(payload)).toString();
        } catch (CharacterCodingException error) {
            throw new IOException("Module response is not UTF-8", error);
        }
        return decodeReply(text, id, operation);
    }

    private static byte[] readExactly(InputStream input, int count) throws IOException {
        byte[] bytes = new byte[count];
        int offset = 0;
        while (offset < count) {
            int read = input.read(bytes, offset, count - offset);
            if (read < 0) throw new EOFException("Truncated module frame");
            if (read == 0) {
                int value = input.read();
                if (value < 0) throw new EOFException("Truncated module frame");
                bytes[offset++] = (byte) value;
            } else {
                offset += read;
            }
        }
        return bytes;
    }

    static Reply decodeReply(String text, String expectedId, String expectedOperation) throws IOException {
        Reply reply = new Reply();
        Set<String> seen = new HashSet<>();
        try (JsonReader reader = new JsonReader(new StringReader(text))) {
            reader.setStrictness(Strictness.STRICT);
            reader.beginObject();
            while (reader.hasNext()) {
                String key = reader.nextName();
                if (!seen.add(key)) throw new IOException("Duplicate module response field");
                switch (key) {
                    case "version": reply.version = integer(reader); break;
                    case "id": reply.id = string(reader, 36); break;
                    case "operation": reply.operation = string(reader, 32); break;
                    case "code": reply.code = string(reader, 64); break;
                    case "exitCode": reply.exitCode = integer(reader); break;
                    case "stdout": reply.stdout = string(reader, MAX_OUTPUT); break;
                    case "stderr": reply.stderr = string(reader, MAX_OUTPUT); break;
                    case "timedOut": reply.timedOut = bool(reader); break;
                    case "executed": reply.executed = bool(reader); break;
                    case "capabilities":
                        requireToken(reader, JsonToken.BEGIN_ARRAY);
                        reader.beginArray();
                        List<String> capabilities = new ArrayList<>();
                        while (reader.hasNext()) {
                            String capability = string(reader, 32);
                            if (capabilities.size() >= 16 || capabilities.contains(capability)) {
                                throw new IOException("Invalid module capabilities");
                            }
                            capabilities.add(capability);
                        }
                        reader.endArray();
                        reply.capabilities = Collections.unmodifiableList(capabilities);
                        break;
                    case "serverVersion": reply.serverVersion = string(reader, 64); break;
                    case "authorization": reply.authorization = string(reader, 16); break;
                    default: throw new IOException("Unrecognized module response field");
                }
            }
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) throw new IOException("Trailing module JSON");
        } catch (IllegalStateException | NumberFormatException error) {
            throw new IOException("Malformed module response", error);
        }
        if (!seen.containsAll(REQUIRED) || reply.version != VERSION
                || !expectedId.equals(reply.id) || !expectedOperation.equals(reply.operation)) {
            throw new IOException("Module response identity or version mismatch");
        }
        if (!reply.code.matches("[a-z_]{1,64}")
                || ("ok".equals(reply.code) && (reply.exitCode != 0 || reply.timedOut))
                || (!"ok".equals(reply.code) && reply.exitCode == 0)) {
            throw new IOException("Contradictory module result");
        }
        if (!reply.authorization.isEmpty() && !AUTHORIZATION_STATES.contains(reply.authorization)) {
            throw new IOException("Invalid module authorization state");
        }
        if ("authorization".equals(reply.operation) && reply.success()
                && (!"granted".equals(reply.authorization) || !"0".equals(reply.stdout.trim()))) {
            throw new IOException("Authorization success was not verified");
        }
        return reply;
    }

    private static int integer(JsonReader reader) throws IOException {
        requireToken(reader, JsonToken.NUMBER);
        String raw = reader.nextString();
        if (!INTEGER.matcher(raw).matches()) throw new IOException("Non-integral module field");
        return Integer.parseInt(raw);
    }

    private static boolean bool(JsonReader reader) throws IOException {
        requireToken(reader, JsonToken.BOOLEAN);
        return reader.nextBoolean();
    }

    private static String string(JsonReader reader, int maximumBytes) throws IOException {
        requireToken(reader, JsonToken.STRING);
        String value = reader.nextString();
        if (value.getBytes(StandardCharsets.UTF_8).length > maximumBytes) {
            throw new IOException("Module string exceeds size limit");
        }
        return value;
    }

    private static void requireToken(JsonReader reader, JsonToken expected) throws IOException {
        if (reader.peek() != expected) throw new IOException("Incorrect module field type");
    }

    public static final class Reply {
        public int version = VERSION;
        public String id = "";
        public String operation = "";
        public String code = "module_outcome_unknown";
        public int exitCode = 1;
        public String stdout = "";
        public String stderr = "";
        public boolean timedOut;
        public boolean executed;
        public List<String> capabilities = Collections.emptyList();
        public String serverVersion = "";
        public String authorization = "";

        public boolean success() {
            return "ok".equals(code) && exitCode == 0 && !timedOut;
        }

        public boolean permitsLegacyFallback() {
            // No authorization, transport, timeout, command or cleanup error permits a retry.
            return !executed && !timedOut && exitCode != 0 && stdout.isEmpty()
                    && ("incompatible_version".equals(code) || "unsupported_operation".equals(code));
        }

        static Reply failure(String id, String operation, String code, String message,
                boolean timedOut, boolean mightHaveExecuted) {
            Reply reply = new Reply();
            reply.id = id;
            reply.operation = operation;
            reply.code = code;
            reply.stderr = message;
            reply.timedOut = timedOut;
            // Conservative local-only flag: true means execution is possible, not verified.
            // Neither this flag nor a live manager is evidence that network capture is ready.
            reply.executed = mightHaveExecuted;
            return reply;
        }
    }
}
