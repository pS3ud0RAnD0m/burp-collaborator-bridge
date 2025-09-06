package com.ps3ud0rand0m.burp.ui;

import com.ps3ud0rand0m.burp.bridge.HttpBridgeServer;
import com.ps3ud0rand0m.burp.utils.Logger;
import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.Serial;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Control panel for the Collaborator bridge.
 * UI logic is kept here; server lifecycle and HTTP/HTTPS handling are in HttpBridgeServer.
 */
public class CollaboratorBridgePanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private final MontoyaApi api;

    // Defaults are conservative and easy to override.
    private static final String DEFAULT_HOST = "0.0.0.0";
    private static final String DEFAULT_PORT = "8844";
    private static final String DEFAULT_HEADER = "X-API-Key";

    private final JTextField hostField   = new JTextField(DEFAULT_HOST, 12);
    private final JTextField portField   = new JTextField(DEFAULT_PORT, 6);
    private final JTextField headerField = new JTextField(DEFAULT_HEADER, 12);

    // API key is optional; if provided, requests must include it.
    // Use a visible text field so the generated key can be copied easily.
    private final JTextField tokenField  = new JTextField(28);
    private final JButton genTokenButton = new JButton("Generate");

    // Optional HTTPS
    private final JCheckBox httpsCheck            = new JCheckBox("Use HTTPS");
    private final JTextField p12PathField         = new JTextField(24);
    private final JPasswordField p12PasswordField = new JPasswordField(18);
    private final JTextField aliasField           = new JTextField(12);

    private final JButton startButton = new JButton("Start");
    private final JButton stopButton  = new JButton("Stop");

    private final JTextArea statusArea = new JTextArea(10, 84);

    // Server instance reference; guarded by EDT access and server-internal synchronization.
    private HttpBridgeServer server;

    public CollaboratorBridgePanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(8, 8));

        // ----- Controls (top) -----
        JPanel controls = new JPanel(new GridBagLayout());
        controls.setBorder(BorderFactory.createTitledBorder("Collaborator Bridge Controls"));

        GridBagConstraints c = baseGbc();

        // Row 0: Host, Port, Header, Token, Generate
        c.gridy = 0;

        c.gridx = 0; controls.add(new JLabel("Host:"), c);
        c.gridx = 1; c.weightx = 0.2; c.fill = GridBagConstraints.HORIZONTAL; controls.add(hostField, c);

        c.gridx = 2; c.weightx = 0; c.fill = GridBagConstraints.NONE; controls.add(new JLabel("Port:"), c);
        c.gridx = 3; c.weightx = 0; c.fill = GridBagConstraints.HORIZONTAL; controls.add(portField, c);

        c.gridx = 4; c.weightx = 0; c.fill = GridBagConstraints.NONE; controls.add(new JLabel("Header:"), c);
        c.gridx = 5; c.weightx = 0.3; c.fill = GridBagConstraints.HORIZONTAL; controls.add(headerField, c);

        c.gridx = 6; c.weightx = 0; c.fill = GridBagConstraints.NONE; controls.add(new JLabel("Token:"), c);
        c.gridx = 7; c.weightx = 0.4; c.fill = GridBagConstraints.HORIZONTAL; controls.add(tokenField, c);

        c.gridx = 8; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        genTokenButton.addActionListener(e -> tokenField.setText(generateApiKey()));
        controls.add(genTokenButton, c);

        // Row 1: HTTPS, PKCS12 Path, Password, Alias, Start, Stop
        c = baseGbc();
        c.gridy = 1;

        c.gridx = 0; controls.add(httpsCheck, c);

        c.gridx = 1; controls.add(new JLabel("PKCS12 Path:"), c);
        c.gridx = 2; c.gridwidth = 3; c.weightx = 0.6; c.fill = GridBagConstraints.HORIZONTAL; controls.add(p12PathField, c);
        c.gridwidth = 1; c.weightx = 0; c.fill = GridBagConstraints.NONE;

        c.gridx = 5; controls.add(new JLabel("Password:"), c);
        c.gridx = 6; c.weightx = 0.2; c.fill = GridBagConstraints.HORIZONTAL; controls.add(p12PasswordField, c);

        c.gridx = 7; c.weightx = 0; c.fill = GridBagConstraints.NONE; controls.add(new JLabel("Alias:"), c);
        c.gridx = 8; c.weightx = 0.2; c.fill = GridBagConstraints.HORIZONTAL; controls.add(aliasField, c);

        // Row 2: Start / Stop buttons, right-aligned
        c = baseGbc();
        c.gridy = 2;
        c.gridx = 0;
        c.gridwidth = 9;
        c.weightx = 1.0;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.EAST;
        JPanel buttons = new JPanel();
        startButton.addActionListener(e -> startServer());
        stopButton.addActionListener(e -> stopServerSafely());
        buttons.add(startButton);
        buttons.add(stopButton);
        controls.add(buttons, c);

        add(controls, BorderLayout.NORTH);

        // ----- Status (center) -----
        statusArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(statusArea);
        scroll.setBorder(BorderFactory.createTitledBorder("Status"));
        add(scroll, BorderLayout.CENTER);

        appendStatus("Endpoints: /v1/health, /v1/payloads, /v1/interactions");
        appendStatus("Example: curl http://" + hostField.getText() + ":" + portField.getText() + "/v1/health");
    }

    private static GridBagConstraints baseGbc() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        return c;
    }

    private void startServer() {
        final String host   = hostField.getText().trim();
        final String ports  = portField.getText().trim();
        final String header = headerField.getText().trim();
        final String token  = tokenField.getText().trim();

        final boolean useHttps = httpsCheck.isSelected();
        final String p12Path   = p12PathField.getText().trim();
        final String p12Pass   = new String(p12PasswordField.getPassword());
        final String alias     = aliasField.getText().trim();

        final int port;
        try {
            port = Integer.parseInt(ports);
        } catch (NumberFormatException nfe) {
            appendStatus("Invalid port: " + ports);
            return;
        }

        if (server != null && server.isRunning()) {
            appendStatus("Server already running on " + (server.isHttps() ? "https" : "http") +
                    "://" + server.bindHost() + ":" + server.bindPort());
            return;
        }

        if (useHttps && (p12Path.isEmpty() || p12Pass.isEmpty())) {
            appendStatus("HTTPS requires PKCS12 path and password.");
            return;
        }

        new Thread(() -> {
            try {
                HttpBridgeServer s = new HttpBridgeServer(api, host, port, header, token,
                        useHttps, p12Path, p12Pass, alias);
                s.start();
                server = s;
                appendStatus("Started on " + (useHttps ? "https" : "http") + "://" + host + ":" + port);
                if (!token.isEmpty()) {
                    appendStatus("Auth: send header '" + header + "'.");
                }
            } catch (IllegalStateException ex) {
                appendStatus("Failed to start: Burp Collaborator is disabled in settings.");
                Logger.logError("Collaborator disabled: " + ex);
            } catch (Exception ex) {
                appendStatus("Failed to start: " + ex);
                Logger.logError("Start error: " + ex);
            }
        }, "collab-bridge-start").start();
    }

    public void stopServerSafely() {
        final HttpBridgeServer s = server;
        if (s == null || !s.isRunning()) {
            appendStatus("Server not running.");
            return;
        }
        new Thread(() -> {
            try {
                s.stop();
                appendStatus("Stopped.");
            } catch (Exception ex) {
                appendStatus("Stop error: " + ex);
                Logger.logError("Stop error: " + ex);
            } finally {
                server = null;
            }
        }, "collab-bridge-stop").start();
    }

    private void appendStatus(String line) {
        SwingUtilities.invokeLater(() -> {
            statusArea.append(line + System.lineSeparator());
            statusArea.setCaretPosition(statusArea.getDocument().getLength());
        });
    }

    /**
     * Generates a URL-safe API key. Base64url-encoded 32 random bytes; no padding.
     */
    private static String generateApiKey() {
        byte[] buf = new byte[32];
        new SecureRandom().nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
