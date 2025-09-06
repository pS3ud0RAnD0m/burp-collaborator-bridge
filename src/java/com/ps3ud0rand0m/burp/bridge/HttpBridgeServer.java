package com.ps3ud0rand0m.burp.bridge;

import com.ps3ud0rand0m.burp.utils.Logger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.PayloadOption;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.SSLEngine;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
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
 * Embedded HTTP/HTTPS bridge around Burp Collaborator.
 *
 * Endpoints:
 *   GET  /v1/health
 *   GET  /v1/payloads  | POST /v1/payloads     (custom, without_server=1)
 *   GET  /v1/interactions                       (payload, id, since, types, limit)
 *
 * Notes:
 * - API key is optional. If set, requests must include the header name/value.
 * - HTTPS is optional. If enabled, provide a PKCS#12 keystore path and password.
 * - State is guarded via a private lock to avoid thread-safety warnings.
 */
public final class HttpBridgeServer {

    private static final String CONTENT_TYPE_JSON = "application/json; charset=utf-8";
    private static final String ERR_UNAUTHORIZED   = "unauthorized";
    private static final String ERR_DISABLED       = "collaborator_disabled";
    private static final int DEFAULT_BACKLOG       = 0;

    private final MontoyaApi api;

    private final String bindHost;
    private final int    bindPort;

    private final String apiKeyHeaderName;
    private final String apiKey; // optional

    private final boolean useHttps;
    private final String  p12Path;     // required if useHttps
    private final String  p12Password; // required if useHttps
    private final String  keyAlias;    // optional

    // guarded by stateLock
    private CollaboratorClient client;
    private HttpServer         server;
    private ExecutorService    executor;
    private final Object       stateLock = new Object();

    public HttpBridgeServer(MontoyaApi api,
                            String bindHost,
                            int bindPort,
                            String apiKeyHeaderName,
                            String apiKey,
                            boolean useHttps,
                            String p12Path,
                            String p12Password,
                            String keyAlias) {
        this.api = api;
        this.bindHost = bindHost;
        this.bindPort = bindPort;
        this.apiKeyHeaderName = (apiKeyHeaderName == null || apiKeyHeaderName.isBlank()) ? "X-API-Key" : apiKeyHeaderName;
        this.apiKey = apiKey == null ? "" : apiKey;

        this.useHttps = useHttps;
        this.p12Path = p12Path == null ? "" : p12Path;
        this.p12Password = p12Password == null ? "" : p12Password;
        this.keyAlias = keyAlias == null ? "" : keyAlias;
    }

    public void start() throws IOException {
        synchronized (stateLock) {
            if (server != null) return; // already running

            // Throws IllegalStateException if Collaborator is disabled.
            this.client = api.collaborator().createClient();

            if (useHttps) {
                this.server = createHttpsServer(bindHost, bindPort, p12Path, p12Password, keyAlias);
            } else {
                this.server = HttpServer.create(new InetSocketAddress(bindHost, bindPort), DEFAULT_BACKLOG);
            }

            this.executor = Executors.newFixedThreadPool(4);
            this.server.setExecutor(executor);

            server.createContext("/v1/health", this::handleHealth);
            server.createContext("/v1/payloads", this::handlePayloads);
            server.createContext("/v1/interactions", this::handleInteractions);

            server.start();
        }
        Logger.logInfo("Collaborator bridge listening on " + (useHttps ? "https" : "http") +
                "://" + bindHost + ":" + bindPort);
    }

    public void stop() {
        synchronized (stateLock) {
            stopHttpServer();
            shutdownExecutor();
            client = null;
        }
    }

    public boolean isRunning() {
        synchronized (stateLock) {
            return server != null;
        }
    }

    public boolean isHttps() {
        return useHttps;
    }

    public String bindHost() {
        return bindHost;
    }

    public int bindPort() {
        return bindPort;
    }

    // ------------------- Handlers -------------------

    private void handleHealth(HttpExchange ex) throws IOException {
        if (isUnauthorized(ex)) return;
        respondJson(ex, 200, "{\"status\":\"ok\"}");
    }

    private void handlePayloads(HttpExchange ex) throws IOException {
        if (isUnauthorized(ex)) return;

        final CollaboratorClient c;
        synchronized (stateLock) { c = client; }
        if (c == null) {
            respondError(ex, 503, ERR_DISABLED);
            return;
        }

        try {
            Map<String, String> q = new HashMap<>(parseQuery(ex.getRequestURI().getRawQuery()));
            if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
                q.putAll(parseJsonObjectFlat(readBody(ex)));
            }

            String custom = trimToEmpty(q.get("custom"));
            boolean withoutServer = "1".equals(q.get("without_server"));

            CollaboratorPayload payload;
            if (!custom.isEmpty()) {
                // Collaborator custom data is alphanumeric and up to 16 chars.
                if (!custom.matches("^[A-Za-z0-9]{1,16}$")) {
                    respondError(ex, 400, "invalid_custom");
                    return;
                }
                payload = withoutServer
                        ? c.generatePayload(custom, PayloadOption.WITHOUT_SERVER_LOCATION)
                        : c.generatePayload(custom);
            } else {
                payload = withoutServer
                        ? c.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION)
                        : c.generatePayload();
            }

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
            respondJson(ex, 200, sb.toString());
        } catch (IllegalStateException e) {
            respondError(ex, 503, ERR_DISABLED);
        } catch (Exception e) {
            Logger.logError("payloads handler error: " + e);
            respondError(ex, 500, "server_error");
        }
    }

    private void handleInteractions(HttpExchange ex) throws IOException {
        if (isUnauthorized(ex)) return;

        final CollaboratorClient c;
        synchronized (stateLock) { c = client; }
        if (c == null) {
            respondError(ex, 503, ERR_DISABLED);
            return;
        }

        try {
            Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
            String byPayload = trimToEmpty(q.get("payload"));
            String byId      = trimToEmpty(q.get("id"));
            String typesCsv  = trimToEmpty(q.get("types")).toLowerCase(Locale.ROOT);
            Set<String> typeWhitelist = parseTypes(typesCsv);

            ZonedDateTime since = null;
            String sinceRaw = trimToEmpty(q.get("since"));
            if (!sinceRaw.isEmpty()) {
                since = parseSince(sinceRaw);
                if (since == null) {
                    respondError(ex, 400, "invalid_since");
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
            respondJson(ex, 200, json);
        } catch (IllegalStateException e) {
            respondError(ex, 503, ERR_DISABLED);
        } catch (Exception e) {
            Logger.logError("interactions handler error: " + e);
            respondError(ex, 500, "server_error");
        }
    }

    // ------------------- Auth / Server lifecycle -------------------

    private boolean isUnauthorized(HttpExchange ex) throws IOException {
        if (apiKey == null || apiKey.isEmpty()) return false;
        String hdr = ex.getRequestHeaders().getFirst(apiKeyHeaderName);
        if (apiKey.equals(hdr)) return false;
        respondError(ex, 401, ERR_UNAUTHORIZED);
        return true;
    }

    private void stopHttpServer() {
        try {
            if (server != null) {
                server.stop(0);
                server = null;
            }
        } catch (Exception e) {
            Logger.logError("HTTP server stop error: " + e);
        }
    }

    private void shutdownExecutor() {
        try {
            if (executor != null) {
                executor.shutdownNow();
                executor = null;
            }
        } catch (Exception e) {
            Logger.logError("Executor shutdown error: " + e);
        }
    }

    private static HttpsServer createHttpsServer(String host, int port, String p12Path, String p12Password, String alias) throws IOException {
        try {
            SSLContext ctx = buildSslContext(p12Path, p12Password, alias);
            HttpsServer https = HttpsServer.create(new InetSocketAddress(host, port), DEFAULT_BACKLOG);
            https.setHttpsConfigurator(new HttpsConfigurator(ctx));
            return https;
        } catch (Exception e) {
            throw new IOException("Failed to initialize HTTPS: " + e.getMessage(), e);
        }
    }

    private static SSLContext buildSslContext(String p12Path, String p12Password, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(p12Path)) {
            ks.load(fis, p12Password.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, p12Password.toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        if (alias != null && !alias.isBlank()) {
            for (int i = 0; i < kms.length; i++) {
                if (kms[i] instanceof X509KeyManager xkm) {
                    kms[i] = new FixedAliasKeyManager(xkm, alias);
                }
            }
        }

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kms, null, null);
        return ctx;
    }

    /**
     * Key manager that always prefers a specific alias when the engine/socket selects a server key.
     */
    private static final class FixedAliasKeyManager extends X509ExtendedKeyManager {
        private final X509KeyManager delegate;
        private final String alias;

        FixedAliasKeyManager(X509KeyManager delegate, String alias) {
            this.delegate = delegate;
            this.alias = alias;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return alias;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return alias;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return delegate.getCertificateChain(alias);
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return delegate.getClientAliases(keyType, issuers);
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return delegate.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return delegate.getServerAliases(keyType, issuers);
        }

        @Override
        public java.security.PrivateKey getPrivateKey(String alias) {
            return delegate.getPrivateKey(alias);
        }
    }

    // ------------------- Parsing / JSON helpers -------------------

    private static Integer parsePositiveInt(String s) {
        if (s.isEmpty()) return null;
        try {
            int v = Integer.parseInt(s);
            return v > 0 ? v : null;
        } catch (NumberFormatException e) {
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
        if (!byPayload.isEmpty()) {
            return c.getInteractions(InteractionFilter.interactionPayloadFilter(byPayload));
        }
        if (!byId.isEmpty()) {
            return c.getInteractions(InteractionFilter.interactionIdFilter(byId));
        }
        return c.getAllInteractions();
    }

    private static List<Interaction> filterInteractions(List<Interaction> in, ZonedDateTime since, Set<String> types) {
        List<Interaction> out = new ArrayList<>(in.size());
        for (Interaction i : in) {
            boolean timeOk = (since == null) || !i.timeStamp().isBefore(since);
            boolean typeOk = types.isEmpty() || types.contains(classifyType(i));
            if (timeOk && typeOk) {
                out.add(i);
            }
        }
        out.sort(Comparator.comparing(Interaction::timeStamp).reversed());
        return out;
    }

    private static void respondError(HttpExchange ex, int code, String err) throws IOException {
        respondJson(ex, code, "{\"error\":\"" + escape(err) + "\"}");
    }

    private static void respondJson(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", CONTENT_TYPE_JSON);
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody()) {
            byte[] buf = is.readAllBytes();
            return new String(buf, StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseQuery(String raw) {
        if (raw == null || raw.isEmpty()) return Collections.emptyMap();
        Map<String, String> m = new HashMap<>();
        for (String pair : raw.split("&")) {
            int idx = pair.indexOf('=');
            String k = idx >= 0 ? pair.substring(0, idx) : pair;
            String v = idx >= 0 ? pair.substring(idx + 1) : "";
            m.put(urlDecode(k), urlDecode(v));
        }
        return m;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    // Minimal flat JSON object parser: {"k":"v",...} → Map<String,String>.
    private static Map<String, String> parseJsonObjectFlat(String body) {
        final String b = body == null ? "" : body.trim();
        if (b.length() < 2 || b.charAt(0) != '{' || b.charAt(b.length() - 1) != '}') {
            return Collections.emptyMap();
        }
        String inner = b.substring(1, b.length() - 1).trim();
        if (inner.isEmpty()) return Collections.emptyMap();

        List<String> parts = splitTopLevel(inner);
        Map<String, String> out = new HashMap<>(Math.max(4, parts.size()));
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
            if (c == '"' && (i == 0 || s.charAt(i - 1) != '\\')) {
                depth ^= 1;
            }
            if (c == ',' && depth == 0) {
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

    private static ZonedDateTime parseSince(String raw) {
        try {
            if (raw.matches("^\\d{10,}$")) {
                long ms = Long.parseLong(raw);
                if (raw.length() == 10) ms *= 1000L;
                return ZonedDateTime.ofInstant(Instant.ofEpochMilli(ms), ZonedDateTime.now().getZone());
            }
            return ZonedDateTime.parse(raw);
        } catch (DateTimeParseException | NumberFormatException e) {
            return null;
        }
    }

    private static String classifyType(Interaction i) {
        if (i.dnsDetails().isPresent())  return "dns";
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
}
