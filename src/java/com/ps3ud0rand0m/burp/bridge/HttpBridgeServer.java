package com.ps3ud0rand0m.burp.bridge;

import com.ps3ud0rand0m.burp.utils.Logger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.PayloadOption;
import burp.api.montoya.collaborator.SmtpDetails;
import burp.api.montoya.http.message.HttpHeader;

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
import java.util.Base64;
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
 * Tiny HTTP/1.1 bridge exposing Burp Collaborator via JSON.
 *
 * <p><strong>Endpoints</strong></p>
 * <ul>
 *   <li>{@code GET /health}</li>
 *   <li>{@code GET|POST /payload} — create a payload; supports {@code custom} (alnum ≤16) and {@code without_server=1}</li>
 *   <li>{@code GET /interactions} — return all interactions seen by this bridge instance
 *       (append-only retention). Each item includes {@code "new":true|false} to indicate whether
 *       it arrived in the current request.</li>
 * </ul>
 *
 * <p><strong>Threading</strong></p>
 * Single instance guarded by {@code stateLock}. Per-connection handling uses a worker thread.
 *
 * <p><strong>Failure model</strong></p>
 * I/O/parse errors return 4xx/5xx. If Collaborator is disabled, endpoints return 503 with
 * {@code error:'collaborator_disabled'}. JSON bodies always end with a single LF.
 */
public final class HttpBridgeServer {

    private static final String CONTENT_TYPE_JSON = "application/json; charset=utf-8";
    private static final String ERR_DISABLED = "collaborator_disabled";

    private static final int MAX_START_LINE = 8192;
    private static final int MAX_HEADER_LINE = 8192;
    private static final int MAX_HEADERS = 200;
    private static final int MAX_BODY = 1_000_000; // 1MB cap for POST body
    private static final int ACCEPT_SO_TIMEOUT_MS = 0;      // blocking accept
    private static final int SOCKET_SO_TIMEOUT_MS = 15_000; // per-client read timeout

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

    // ---------------- Retention (append-only, no filtering) ----------------
    /**
     * Retained interactions and their first-seen sequence number. The sequence increments once
     * per /interactions request that actually receives fresh items from Collaborator.
     */
    private final Object cacheLock = new Object();
    private final Map<String, Cached> cache = new HashMap<>(); // key -> cached
    private long pollSeq = 0L; // incremented when new items arrive in a request

    /** Minimal holder for retention. */
    private record Cached(Interaction it, long seq) { }
    // ----------------------------------------------------------------------

    /** Create a bridge bound to the provided host/port. */
    public HttpBridgeServer(MontoyaApi api, String bindHost, int bindPort) {
        this.api = api;
        this.bindHost = bindHost;
        this.bindPort = bindPort;
    }

    /** Start the server: create a Collaborator client, bind the socket, and spawn the accept loop. */
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

    /** Stop the server and worker pool; safe to call multiple times. */
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

    /** Handle a single request (one per TCP connection). */
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
                case "/payload":
                    handlePayload(req, rawOut);
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

    private void handlePayload(HttpRequest req, OutputStream out) throws IOException {
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

            writeJson(out, 200, payloadJson(payload));
        } catch (IllegalStateException _ ) {
            writeJson(out, 503, errorJson(ERR_DISABLED));
        } catch (IllegalArgumentException bad) {
            writeJson(out, 400, errorJson("invalid_custom".equals(bad.getMessage()) ? "invalid_custom" : "bad_request"));
        } catch (Exception e) {
            Logger.logError("payload handler error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            writeJson(out, 500, errorJson("server_error"));
        }
    }

    /** Build a payload from inputs. Validates {@code custom} as alnum ≤16 and respects {@code withoutServer}. */
    private static CollaboratorPayload createPayload(CollaboratorClient c, String custom, boolean withoutServer) {
        final String customValue = trimToEmpty(custom);
        if (!customValue.isEmpty()) {
            if (!customValue.matches("^[A-Za-z0-9]{1,16}$")) {
                throw new IllegalArgumentException("invalid_custom");
            }
            return withoutServer
                    ? c.generatePayload(customValue, PayloadOption.WITHOUT_SERVER_LOCATION)
                    : c.generatePayload(customValue);
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
            Filters f = filtersFromQuery(req.query());
            if (f.invalidSince()) {
                writeJson(out, 400, errorJson("invalid_since"));
                return;
            }

            // 1) Poll once; append fresh results to retention.
            long currentSeq = pollAndRetain(c);

            // 2) Return full retained set (no filtering), marking "new" for this request.
            writeJson(out, 200, listInteractionsJsonFromRetention(currentSeq));
        } catch (IllegalStateException _ ) {
            writeJson(out, 503, errorJson(ERR_DISABLED));
        } catch (Exception e) {
            Logger.logError("interactions handler error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            writeJson(out, 500, errorJson("server_error"));
        }
    }

    // --------------------- HTTP parse helpers ---------------------

    /** Minimal container parsed from the raw socket. */
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

        String[] parts = splitRequestLine(start);
        if (parts == null) return null;

        String method  = parts[0];
        String uri     = parts[1];
        String version = parts[2];

        Map<String, String> headers = readHeaders(in);
        if (headers == null) return null;

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

    /** Split the request line into 3 parts; return null if malformed. */
    private static String[] splitRequestLine(String start) {
        String[] parts = start.split(" ", 3);
        return (parts.length < 3) ? null : new String[] { parts[0].toUpperCase(Locale.ROOT), parts[1], parts[2] };
    }

    /** Read headers until a blank line; null if EOF encountered unexpectedly. */
    @SuppressWarnings("java:S1168")
    private static Map<String, String> readHeaders(InputStream in) throws IOException {
        Map<String, String> headers = new HashMap<>();
        for (int i = 0; i < MAX_HEADERS; i++) {
            String line = readLine(in, MAX_HEADER_LINE);
            if (line == null) return null; // sentinel for truncated/EOF before CRLFCRLF
            if (line.isEmpty()) break;
            int idx = line.indexOf(':');
            if (idx > 0) {
                String k = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
                String v = line.substring(idx + 1).trim();
                headers.put(k, v);
            }
        }
        return headers;
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

    /** Write a JSON response with a trailing LF and a correct {@code Content-Length}. */
    private static void writeJson(OutputStream out, int code, String body) throws IOException {
        if (!body.endsWith("\n")) { body = body + "\n"; }
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

    /** Flat JSON object parser used for POST bodies (no nesting). */
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

    // Split a comma-separated list while ignoring commas inside quotes.
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

    // Remove surrounding quotes and unescape \" and \\.
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

    /** Parsed /interactions filters (parsed only to validate; not used to filter output). */
    private record Filters(String byPayload, String byId, Set<String> typeWhitelist,
                           ZonedDateTime since, Integer limit, boolean invalidSince) { }

    private static Filters filtersFromQuery(Map<String, String> qRaw) {
        // Parse/validate inputs to keep request semantics stable (e.g., invalid_since).
        Map<String, String> q = (qRaw == null) ? Collections.emptyMap() : qRaw;

        String byPayload = trimToEmpty(q.get("payload"));
        String byId = trimToEmpty(q.get("id"));

        String typesCsv = trimToEmpty(q.get("types")).toLowerCase(Locale.ROOT);
        Set<String> typeWhitelist = parseTypes(typesCsv);

        String sinceRaw = trimToEmpty(q.get("since"));
        ZonedDateTime since = null;
        boolean bad = false;
        if (!sinceRaw.isEmpty()) {
            since = parseSince(sinceRaw);
            bad = (since == null);
        }

        Integer limit = parsePositiveInt(trimToEmpty(q.get("limit")));

        return new Filters(byPayload, byId, typeWhitelist, since, limit, bad);
    }

    /**
     * Poll Collaborator once and append any fresh interactions to retention.
     * @return the current sequence number used to tag "new" items for this request;
     *         if nothing new arrived, returns {@code -1}.
     */
    private long pollAndRetain(CollaboratorClient c) {
        List<Interaction> fresh;
        try {
            fresh = c.getAllInteractions(); // poll (consumes new/unread items)
        } catch (Exception e) {
            Logger.logError("Collaborator poll failed: " + e.getMessage());
            return -1;
        }
        if (fresh == null || fresh.isEmpty()) return -1;

        long seq;
        synchronized (cacheLock) {
            seq = ++pollSeq;
            final long s = seq; // effectively final for lambda capture
            for (Interaction it : fresh) {
                String key = keyOf(it);
                // putIfAbsent avoids the "unused lambda parameter" warning from computeIfAbsent
                cache.putIfAbsent(key, new Cached(it, s));
            }
        }
        return seq;
    }

    /** Compose a stable key for dedupe across polls. */
    private static String keyOf(Interaction it) {
        return it.id() + "|" + it.type().name() + "|" + it.timeStamp() + "|" +
                it.clientIp().getHostAddress() + ":" + it.clientPort();
    }

    /** Build JSON from retention (all items), tagging those first seen in {@code currentSeq} as {@code "new":true}. */
    private String listInteractionsJsonFromRetention(long currentSeq) {
        List<Cached> snapshot;
        synchronized (cacheLock) {
            snapshot = new ArrayList<>(cache.values());
        }

        // newest-first
        snapshot.sort(Comparator.comparing((Cached c) -> c.it.timeStamp()).reversed());

        StringJoiner j = new StringJoiner(",", "[", "]");
        for (Cached c : snapshot) {
            boolean isNew = (currentSeq != -1) && (c.seq == currentSeq);
            j.add(interactionToJson(c.it, isNew));
        }
        return j.toString();
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

    /** Serialize one interaction (helpers handle per-type detail). */
    private static String interactionToJson(Interaction i, boolean isNew) {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        jsonField(sb, "id", i.id().toString());
        sb.append(',');
        jsonField(sb, "type", i.type().name().toLowerCase(Locale.ROOT));
        sb.append(',');
        jsonField(sb, "timestamp", i.timeStamp().toString());
        sb.append(',');
        jsonField(sb, "clientIp", i.clientIp().getHostAddress());
        sb.append(',');
        sb.append("\"clientPort\":").append(i.clientPort());
        sb.append(',');
        jsonField(sb, "new", isNew);

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

        i.dnsDetails().ifPresent(dd -> appendDns(sb, dd));
        i.httpDetails().ifPresent(hd -> appendHttp(sb, hd));
        i.smtpDetails().ifPresent(sd -> appendSmtp(sb, sd));

        sb.append('}');
        return sb.toString();
    }

    /** Append DNS block. */
    private static void appendDns(StringBuilder sb, DnsDetails dd) {
        sb.append(',');
        sb.append("\"dns\":{");
        jsonField(sb, "queryType", dd.queryType().name());
        sb.append(',');
        byte[] raw = dd.query().getBytes();
        jsonField(sb, "qname", decodeDnsQname(raw));
        sb.append(',');
        jsonField(sb, "rawQueryBase64", base64(raw));
        sb.append('}');
    }

    /** Append HTTP block (service + request + optional response + optional timing). */
    private static void appendHttp(StringBuilder sb, HttpDetails hd) {
        sb.append(',');
        sb.append("\"http\":{");
        jsonField(sb, "protocol", hd.protocol().name());

        burp.api.montoya.http.message.HttpRequestResponse rr = hd.requestResponse();
        burp.api.montoya.http.message.requests.HttpRequest req = rr.request();

        sb.append(',');
        appendServiceBlock(sb, req);
        sb.append(',');
        appendRequestBlock(sb, req);

        if (rr.hasResponse()) {
            sb.append(',');
            appendResponseBlock(sb, rr.response());
        }

        appendTimingBlock(sb, rr);

        sb.append('}');
    }

    private static void appendServiceBlock(StringBuilder sb, burp.api.montoya.http.message.requests.HttpRequest req) {
        sb.append("\"service\":{");
        burp.api.montoya.http.HttpService svc = req.httpService();
        jsonField(sb, "host", svc.host());
        sb.append(',');
        sb.append("\"port\":").append(svc.port());
        sb.append(',');
        jsonField(sb, "secure", svc.secure());
        sb.append('}');
    }

    private static void appendRequestBlock(StringBuilder sb, burp.api.montoya.http.message.requests.HttpRequest req) {
        sb.append("\"request\":{");
        jsonField(sb, "method", req.method());
        sb.append(',');
        jsonField(sb, "httpVersion", req.httpVersion());
        sb.append(',');
        jsonField(sb, "path", req.path());
        sb.append(',');
        jsonField(sb, "pathWithoutQuery", req.pathWithoutQuery());
        sb.append(',');
        jsonField(sb, "query", req.query());
        sb.append(',');
        jsonField(sb, "url", req.url());
        sb.append(',');
        appendHeadersBodyRaw(sb, req.headers(), req.body().getBytes(), req.toByteArray().getBytes());
        sb.append('}');
    }

    private static void appendResponseBlock(StringBuilder sb, burp.api.montoya.http.message.responses.HttpResponse resp) {
        sb.append("\"response\":{");
        sb.append("\"statusCode\":").append(resp.statusCode());
        sb.append(',');
        jsonField(sb, "reasonPhrase", resp.reasonPhrase());
        sb.append(',');
        appendHeadersBodyRaw(sb, resp.headers(), resp.body().getBytes(), resp.toByteArray().getBytes());
        sb.append('}');
    }

    private static void appendTimingBlock(StringBuilder sb, burp.api.montoya.http.message.HttpRequestResponse rr) {
        try {
            rr.timingData().ifPresent(td -> {
                sb.append(',');
                sb.append("\"timing\":{");
                jsonField(sb, "timeRequestSent", td.timeRequestSent().toString());
                sb.append(',');
                jsonField(sb, "timeToFirstByte",
                        td.timeBetweenRequestSentAndStartOfResponse() == null ? "" :
                                td.timeBetweenRequestSentAndStartOfResponse().toString());
                sb.append(',');
                jsonField(sb, "timeToLastByte",
                        td.timeBetweenRequestSentAndEndOfResponse() == null ? "" :
                                td.timeBetweenRequestSentAndEndOfResponse().toString());
                sb.append('}');
            });
        } catch (Exception _ ) {
            // Some RR implementations may not expose timing data; ignore safely.
        }
    }

    /** Append SMTP block. */
    private static void appendSmtp(StringBuilder sb, SmtpDetails sd) {
        sb.append(',');
        sb.append("\"smtp\":{");
        jsonField(sb, "protocol", sd.protocol().name());
        sb.append(',');
        jsonField(sb, "conversation", sd.conversation());
        sb.append('}');
    }

    /** Emit fields "headers", "bodyBase64", and "rawBase64" in that order. */
    private static void appendHeadersBodyRaw(StringBuilder sb, List<HttpHeader> headers, byte[] body, byte[] raw) {
        sb.append("\"headers\":").append(headersArray(headers));
        sb.append(',');
        jsonField(sb, "bodyBase64", base64(body));
        sb.append(',');
        jsonField(sb, "rawBase64", base64(raw));
    }

    /** Serialize HTTP headers as an array of objects with fields {@code name} and {@code value}. */
    private static String headersArray(List<HttpHeader> headers) {
        StringJoiner j = new StringJoiner(",", "[", "]");
        for (HttpHeader h : headers) {
            StringBuilder sb = new StringBuilder(64);
            sb.append('{');
            jsonField(sb, "name", h.name());
            sb.append(',');
            jsonField(sb, "value", h.value());
            sb.append('}');
            j.add(sb.toString());
        }
        return j.toString();
    }

    /** Base64 utility; treats {@code null} as empty. */
    private static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data == null ? new byte[0] : data);
    }

    /**
     * Minimal DNS QNAME decoder (supports compression). Implemented with early returns (no break/continue clutter).
     */
    private static String decodeDnsQname(byte[] msg) {
        if (msg == null || msg.length < 12) return "";
        return readDnsName(msg, 12, new HashSet<>());
    }

    /**
     * Recursive helper for DNS name decoding.
     * Stops on zero-length label or compression pointer; bounds guarded.
     */
    private static String readDnsName(byte[] msg, int pos, Set<Integer> visited) {
        StringBuilder name = new StringBuilder();
        int current = pos;
        int safety = 0;

        while (current < msg.length && safety++ < 512) {
            int len = msg[current] & 0xFF;

            // end of name
            if (len == 0) return name.toString();

            // compression pointer
            if ((len & 0xC0) == 0xC0) {
                if (current + 1 >= msg.length) return name.toString();
                int ptr = ((len & 0x3F) << 8) | (msg[current + 1] & 0xFF);
                if (ptr >= msg.length || !visited.add(ptr)) return name.toString();
                String pointed = readDnsName(msg, ptr, visited);
                if (!pointed.isEmpty()) {
                    if (!name.isEmpty()) name.append('.');
                    name.append(pointed);
                }
                return name.toString(); // pointer terminates the name
            }

            // regular label
            int end = current + 1 + len;
            if (end > msg.length) return name.toString();
            if (!name.isEmpty()) name.append('.');
            name.append(new String(msg, current + 1, len, StandardCharsets.UTF_8));
            current = end;
        }
        return name.toString();
    }

    private static void jsonField(StringBuilder sb, String k, String v) {
        sb.append('"').append(escape(k)).append("\":\"").append(escape(v == null ? "" : v)).append('"');
    }

    private static void jsonField(StringBuilder sb, String k, boolean v) {
        sb.append('"').append(escape(k)).append("\":").append(v ? "true" : "false");
    }

    /** String escape for JSON (minimal subset used here). */
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

    private static String httpUrlForLog(String host, int port) {
        return "http://" + host + ":" + port;
    }

    // --------------------- payload helpers ---------------------

    private static String payloadJson(CollaboratorPayload p) {
        StringBuilder sb = new StringBuilder(128);
        sb.append('{');
        jsonField(sb, "payload", p.toString());
        sb.append(',');
        jsonField(sb, "id", p.id().toString());
        p.customData().ifPresent(cd -> {
            sb.append(',');
            jsonField(sb, "customData", cd);
        });
        p.server().ifPresent(loc -> {
            sb.append(',');
            jsonField(sb, "serverLocation", loc.toString());
        });
        sb.append('}');
        return sb.toString();
    }
}
