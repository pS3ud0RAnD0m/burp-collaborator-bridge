package com.ps3ud0rand0m.burp.bridge;

import com.ps3ud0rand0m.burp.utils.Logger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.PayloadOption;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Minimal HTTP/1.1 server (no jdk.httpserver dependency).
 *
 * Endpoints:
 *   GET  /health
 *   GET  /payloads | POST /payloads  (custom, without_server=1)
 *   GET  /interactions             (payload, id, since, types, limit)
 *
 * Single-request per connection; the socket is closed after each response.
 */
public final class HttpBridgeServer {

    private static final String CONTENT_TYPE_JSON = "application/json; charset=utf-8";
    private static final String ERR_DISABLED = "collaborator_disabled";

    private static final int MAX_START_LINE = 8192;
    private static final int MAX_HEADER_LINE = 8192;
    private static final int MAX_HEADERS = 200;
    private static final int MAX_BODY = 1_000_000; // 1MB cap for POST body
    private static final int ACCEPT_SO_TIMEOUT_MS = 0;      // blocking accept
    private static final int SOCKET_SO_TIMEOUT_MS = 15_000; // read timeout per client

    private final MontoyaApi api;
    private final String bindHost;
    private final int bindPort;

    // guarded by stateLock
    private final Object stateLock = new Object();
    private volatile boolean running;
    private CollaboratorClient client;
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private Thread acceptThread;

    public HttpBridgeServer(MontoyaApi api, String bindHost, int bindPort) {
        this.api = api;
        this.bindHost = bindHost;
        this.bindPort = bindPort;
    }

    public void start() throws IOException {
        synchronized (stateLock) {
            if (running) return;

            Logger.logInfo("Runtime: java.version=" + System.getProperty("java.version")
                    + " java.vendor=" + System.getProperty("java.vendor")
                    + " os.name=" + System.getProperty("os.name")
                    + " os.arch=" + System.getProperty("os.arch"));

            Logger.logInfo("Creating Collaborator client ...");
            this.client = api.collaborator().createClient();
            Logger.logInfo("Collaborator client created.");

            preflightBind(bindHost, bindPort);

            Logger.logInfo("Opening ServerSocket on " + httpUrlForLog(bindHost, bindPort) + " ...");
            this.serverSocket = new ServerSocket();
            this.serverSocket.setReuseAddress(true);
            this.serverSocket.bind(new InetSocketAddress(InetAddress.getByName(bindHost), bindPort));
            this.serverSocket.setSoTimeout(ACCEPT_SO_TIMEOUT_MS);

            this.executor = Executors.newFixedThreadPool(8);
            this.running = true;

            this.acceptThread = new Thread(this::acceptLoop, "collab-bridge-accept");
            this.acceptThread.setDaemon(true);
            this.acceptThread.start();

            Logger.logInfo("Listening on " + httpUrlForLog(bindHost, bindPort));
        }
    }

    public void stop() {
        synchronized (stateLock) {
            running = false;
            try {
                if (serverSocket != null && !serverSocket.isClosed()) {
                    serverSocket.close(); // unblocks accept()
                }
            } catch (IOException e) {
                Logger.logError("ServerSocket close error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            try {
                if (executor != null) executor.shutdownNow();
            } catch (Exception e) {
                Logger.logError("Executor shutdown error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            serverSocket = null;
            executor = null;
            client = null;
            acceptThread = null;
            Logger.logInfo("HTTP server stopped.");
        }
    }

    public boolean isRunning() {
        synchronized (stateLock) {
            return running;
        }
    }

    public String bindHost() {
        return bindHost;
    }

    public int bindPort() {
        return bindPort;
    }

    // --------------------- Accept loop ---------------------

    private void acceptLoop() {
        Logger.logInfo("Accept loop started.");
        while (running) {
            try {
                final Socket s = serverSocket.accept();
                s.setSoTimeout(SOCKET_SO_TIMEOUT_MS);
                executor.submit(() -> handleClient(s));
            } catch (SocketException se) {
                if (running) {
                    Logger.logError("Accept SocketException: " + se.getMessage());
                }
                break;
            } catch (IOException ioe) {
                if (running) {
                    Logger.logError("Accept IOException: " + ioe.getMessage());
                }
            } catch (Exception e) {
                if (running) {
                    Logger.logError("Accept unexpected error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        }
        Logger.logInfo("Accept loop exiting.");
    }

    // --------------------- Client handling ---------------------

    private void handleClient(Socket socket) {
        try (Socket s = socket;
             InputStream rawIn = new BufferedInputStream(s.getInputStream());
             OutputStream rawOut = new BufferedOutputStream(s.getOutputStream())) {

            HttpRequest req = parseRequest(rawIn);
            if (req == null) return;

            String pathOnly = req.path(); // already without query
            switch (pathOnly) {
                case "/health":
                    writeJson(rawOut, 200, "{\"status\":\"ok\"}");
                    return;
                case "/payloads":
                    handlePayloads(req, rawOut);
                    return;
                case "/interactions":
                    handleInteractions(req, rawOut);
                    return;
                default:
                    writeJson(rawOut, 404, errorJson("not_found"));
            }
        } catch (Exception e) {
            Logger.logError("Client handler error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void handlePayloads(HttpRequest req, OutputStream out) throws IOException {
        final CollaboratorClient c;
        synchronized (stateLock) { c = client; }
        if (c == null) {
            writeJson(out, 503, errorJson(ERR_DISABLED));
            return;
        }

        try {
            Map<String, String> q = new HashMap<>(req.query());
            if ("POST".equals(req.method())) {
                q.putAll(parseJsonObjectFlat(req.body()));
            }

            String custom = trimToEmpty(q.get("custom"));
            boolean withoutServer = "1".equals(q.get("without_server"));

            CollaboratorPayload payload = createPayload(c, custom, withoutServer);

            StringBuilder sb = new StringBuilder(128);
            sb.append('{');
            jsonField(sb, "payload", payload.toString());
            sb.append(',');
            jsonField(sb, "id", payload.id().toString());
            payload.customData().ifPresent(cd -> {
                sb.append(',');
                jsonField(sb, "customData", cd);
            });
            payload.server().ifPresent(loc -> {
                sb.append(',');
                jsonField(sb, "serverLocation", loc.toString());
            });
            sb.append('}');
            writeJson(out, 200, sb.toString());
        } catch (IllegalStateException _ ) {
            writeJson(out, 503, errorJson(ERR_DISABLED));
        } catch (IllegalArgumentException bad) {
            if ("invalid_custom".equals(bad.getMessage())) {
                writeJson(out, 400, errorJson("invalid_custom"));
            } else {
                writeJson(out, 400, errorJson("bad_request"));
            }
        } catch (Exception e) {
            Logger.logError("payloads handler error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            writeJson(out, 500, errorJson("server_error"));
        }
    }

    private static CollaboratorPayload createPayload(CollaboratorClient c, String custom, boolean withoutServer) {
        if (!trimToEmpty(custom).isEmpty()) {
            if (!custom.matches("^[A-Za-z0-9]{1,16}$")) {
                throw new IllegalArgumentException("invalid_custom");
            }
            return withoutServer
                    ? c.generatePayload(custom, PayloadOption.WITHOUT_SERVER_LOCATION)
                    : c.generatePayload(custom);
        }
        return withoutServer
                ? c.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION)
                : c.generatePayload();
    }

    private void handleInteractions(HttpRequest req, OutputStream out) throws IOException {
        final CollaboratorClient c;
        synchronized (stateLock) { c = client; }
        if (c == null) {
            writeJson(out, 503, errorJson(ERR_DISABLED));
            return;
        }

        try {
            Map<String, String> q = req.query();

            String byPayload = trimToEmpty(q.get("payload"));
            String byId      = trimToEmpty(q.get("id"));
            String typesCsv  = trimToEmpty(q.get("types")).toLowerCase(Locale.ROOT);
            Set<String> typeWhitelist = parseTypes(typesCsv);

            ZonedDateTime since = null;
            String sinceRaw = trimToEmpty(q.get("since"));
            if (!sinceRaw.isEmpty()) {
                since = parseSince(sinceRaw);
                if (since == null) {
                    writeJson(out, 400, errorJson("invalid_since"));
                    return;
                }
            }

            Integer limit = parsePositiveInt(trimToEmpty(q.get("limit")));

            List<Interaction> interactions = fetchInteractions(c, byPayload, byId);
            List<Interaction> filtered = filterInteractions(interactions, since, typeWhitelist);
            if (limit != null && filtered.size() > limit) {
                filtered = filtered.subList(0, limit);
            }

            String json = interactionsToJson(filtered);
            writeJson(out, 200, json);
        } catch (IllegalStateException _ ) {
            writeJson(out, 503, errorJson(ERR_DISABLED));
        } catch (Exception e) {
            Logger.logError("interactions handler error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            writeJson(out, 500, errorJson("server_error"));
        }
    }

    // --------------------- HTTP helpers ---------------------

    private record HttpRequest(
            String method,
            String path,
            String version,
            Map<String, String> headers,
            Map<String, String> query,
            String body
    ) {}

    private HttpRequest parseRequest(InputStream in) throws IOException {
        String start = readLine(in, MAX_START_LINE);
        if (start == null || start.isEmpty()) return null;

        String[] parts = start.split(" ", 3);
        if (parts.length < 3) return null;
        String method  = parts[0].toUpperCase(Locale.ROOT);
        String uri     = parts[1];
        String version = parts[2];

        Map<String, String> headers = new HashMap<>();
        for (int i = 0; i < MAX_HEADERS; i++) {
            String line = readLine(in, MAX_HEADER_LINE);
            if (line == null) return null;
            if (line.isEmpty()) break;
            int idx = line.indexOf(':');
            if (idx > 0) {
                String k = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
                String v = line.substring(idx + 1).trim();
                headers.put(k, v);
            }
        }

        String path = uri;
        String rawQuery = null;
        int qIdx = uri.indexOf('?');
        if (qIdx >= 0) {
            path = uri.substring(0, qIdx);
            rawQuery = uri.substring(qIdx + 1);
        }

        int contentLen = 0;
        if ("POST".equals(method) || "PUT".equals(method)) {
            String cl = headers.get("content-length");
            if (cl != null) {
                try { contentLen = Integer.parseInt(cl.trim()); } catch (NumberFormatException _ ) { /* ignore */ }
            }
            if (contentLen < 0 || contentLen > MAX_BODY) {
                return new HttpRequest(method, path, version, headers, parseQuery(rawQuery), "");
            }
        }

        String body = "";
        if (contentLen > 0) {
            byte[] buf = in.readNBytes(contentLen);
            body = new String(buf, StandardCharsets.UTF_8);
        }

        return new HttpRequest(method, path, version, headers, parseQuery(rawQuery), body);
    }

    private static String readLine(InputStream in, int maxLen) throws IOException {
        StringBuilder sb = new StringBuilder(80);
        int prev = -1;
        for (int i = 0; i < maxLen; i++) {
            int b = in.read();
            if (b == -1) break;
            if (b == '\n') {
                int end = sb.length();
                if (end > 0 && prev == '\r') {
                    sb.setLength(end - 1); // trim trailing \r
                }
                return sb.toString();
            }
            sb.append((char) b);
            prev = b;
        }
        return sb.isEmpty() ? null : sb.toString();
    }

    private static void writeJson(OutputStream out, int code, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        String headers =
                "HTTP/1.1 " + code + " " + reasonPhrase(code) + "\r\n" +
                        "Content-Type: " + CONTENT_TYPE_JSON + "\r\n" +
                        "Content-Length: " + payload.length + "\r\n" +
                        "Connection: close\r\n" +
                        "\r\n";
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        out.write(payload);
        out.flush();
    }

    private static String reasonPhrase(int code) {
        return switch (code) {
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 500 -> "Internal Server Error";
            case 503 -> "Service Unavailable";
            default -> "OK";
        };
    }

    private static String errorJson(String code) {
        return "{\"error\":\"" + escape(code) + "\"}";
    }

    // --------------------- Business helpers ---------------------

    private static void preflightBind(String host, int port) {
        try (ServerSocket ss = new ServerSocket()) {
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress(InetAddress.getByName(host), port));
            Logger.logInfo("Preflight bind via ServerSocket SUCCEEDED for " + host + ":" + port + " (closing socket).");
        } catch (Exception e) {
            Logger.logError("Preflight bind via ServerSocket FAILED (" + e.getClass().getSimpleName() + "): " + e.getMessage());
        }
    }

    private static Map<String, String> parseQuery(String raw) {
        if (raw == null || raw.isEmpty()) return Collections.emptyMap();
        Map<String, String> m = new HashMap<>();
        for (String pair : raw.split("&")) {
            int idx = pair.indexOf('=');
            String k = (idx >= 0) ? pair.substring(0, idx) : pair;
            String v = (idx >= 0) ? pair.substring(idx + 1) : "";
            m.put(urlDecode(k), urlDecode(v));
        }
        return m;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception _ ) {
            return s;
        }
    }

    private static Map<String, String> parseJsonObjectFlat(String body) {
        String b = (body == null) ? "" : body.trim();
        if (b.length() < 2 || b.charAt(0) != '{' || b.charAt(b.length() - 1) != '}') return Collections.emptyMap();

        String inner = b.substring(1, b.length() - 1).trim();
        if (inner.isEmpty()) return Collections.emptyMap();

        List<String> parts = splitTopLevel(inner);
        Map<String, String> out = new HashMap<>();
        for (String p : parts) {
            int idx = p.indexOf(':');
            if (idx < 0) continue;
            String k = unquote(p.substring(0, idx).trim());
            String v = unquote(p.substring(idx + 1).trim());
            out.put(k, v);
        }
        return out;
    }

    // Splits a comma-separated string while ignoring commas inside quoted segments.
    private static List<String> splitTopLevel(String s) {
        List<String> parts = new ArrayList<>();
        int depth = 0; // 0 = outside quotes, 1 = inside quotes
        StringBuilder token = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean quoteToggle = (c == '"' && (i == 0 || s.charAt(i - 1) != '\\'));
            if (quoteToggle) {
                depth ^= 1;
            } else if (c == ',' && depth == 0) {
                parts.add(token.toString());
                token.setLength(0);
            } else {
                token.append(c);
            }
        }
        parts.add(token.toString());
        return parts;
    }

    private static String unquote(String s) {
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"') {
            String inner = s.substring(1, s.length() - 1);
            return inner.replace("\\\"", "\"").replace("\\\\", "\\");
        }
        return s;
    }

    private static String trimToEmpty(String s) {
        return (s == null) ? "" : s.trim();
    }

    private static Integer parsePositiveInt(String s) {
        if (s.isEmpty()) return null;
        try {
            int v = Integer.parseInt(s);
            return (v > 0) ? v : null;
        } catch (NumberFormatException _ ) {
            return null;
        }
    }

    private static Set<String> parseTypes(String csv) {
        if (csv.isEmpty()) return Collections.emptySet();
        Set<String> out = new HashSet<>();
        for (String t : csv.split(",")) {
            String v = t.trim();
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }

    private static List<Interaction> fetchInteractions(CollaboratorClient c, String byPayload, String byId) {
        if (!byPayload.isEmpty()) return c.getInteractions(InteractionFilter.interactionPayloadFilter(byPayload));
        if (!byId.isEmpty()) return c.getInteractions(InteractionFilter.interactionIdFilter(byId));
        return c.getAllInteractions();
    }

    private static List<Interaction> filterInteractions(List<Interaction> in, ZonedDateTime since, Set<String> types) {
        List<Interaction> out = new ArrayList<>(in.size());
        for (Interaction i : in) {
            boolean timeOk = (since == null) || !i.timeStamp().isBefore(since);
            boolean typeOk = types.isEmpty() || types.contains(classifyType(i));
            if (timeOk && typeOk) out.add(i);
        }
        out.sort(Comparator.comparing(Interaction::timeStamp).reversed());
        return out;
    }

    private static ZonedDateTime parseSince(String raw) {
        try {
            if (raw.matches("^\\d{10,}$")) {
                long ms = Long.parseLong(raw);
                if (raw.length() == 10) ms *= 1000L;
                return ZonedDateTime.ofInstant(Instant.ofEpochMilli(ms), ZonedDateTime.now().getZone());
            }
            return ZonedDateTime.parse(raw);
        } catch (DateTimeParseException | NumberFormatException _ ) {
            return null;
        }
    }

    private static String classifyType(Interaction i) {
        if (i.dnsDetails().isPresent()) return "dns";
        if (i.httpDetails().isPresent()) return "http";
        if (i.smtpDetails().isPresent()) return "smtp";
        return "unknown";
    }

    private static String interactionsToJson(List<Interaction> list) {
        StringJoiner j = new StringJoiner(",", "[", "]");
        for (Interaction i : list) {
            StringBuilder sb = new StringBuilder(128);
            sb.append('{');
            jsonField(sb, "id", i.id().toString());
            sb.append(',');
            jsonField(sb, "type", classifyType(i));
            sb.append(',');
            jsonField(sb, "timestamp", i.timeStamp().toString());
            sb.append(',');
            jsonField(sb, "clientIp", i.clientIp().getHostAddress());
            sb.append(',');
            sb.append("\"clientPort\":").append(i.clientPort());
            i.customData().ifPresent(cd -> {
                sb.append(',');
                jsonField(sb, "customData", cd);
            });
            sb.append(',');
            jsonField(sb, "hasDns", i.dnsDetails().isPresent());
            sb.append(',');
            jsonField(sb, "hasHttp", i.httpDetails().isPresent());
            sb.append(',');
            jsonField(sb, "hasSmtp", i.smtpDetails().isPresent());
            sb.append('}');
            j.add(sb.toString());
        }
        return j.toString();
    }

    private static void jsonField(StringBuilder sb, String k, String v) {
        sb.append('"').append(escape(k)).append("\":\"").append(escape(v)).append('"');
    }

    private static void jsonField(StringBuilder sb, String k, boolean v) {
        sb.append('"').append(escape(k)).append("\":").append(v ? "true" : "false");
    }

    private static String escape(String s) {
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"':  b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:   b.append(c);
            }
        }
        return b.toString();
    }

    @SuppressWarnings("HttpUrlsUsage")
    private static String httpUrlForLog(String host, int port) {
        return "http://" + host + ":" + port;
    }
}
