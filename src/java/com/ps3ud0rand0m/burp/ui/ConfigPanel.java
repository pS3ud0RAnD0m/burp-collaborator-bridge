package com.ps3ud0rand0m.burp.ui;

import com.ps3ud0rand0m.burp.bridge.HttpBridgeServer;
import com.ps3ud0rand0m.burp.utils.Logger;
import burp.api.montoya.MontoyaApi;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.io.Serial;

/**
 * Configuration panel for the Collaborator bridge.
 * Shows all extension logs inline by implementing Logger.Sink.
 */
public class ConfigPanel extends JPanel implements Logger.Sink {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final String DEFAULT_HOST = "127.0.0.1";
    private static final String DEFAULT_PORT = "8090";

    private final transient MontoyaApi api;

    private final JTextField hostField = new JTextField(DEFAULT_HOST, 16);
    private final JTextField portField = new JTextField(DEFAULT_PORT, 6);

    private final JButton startButton = new JButton("Start");
    private final JButton stopButton  = new JButton("Stop");

    // Single, unified log view for all output (replaces status/log duplication).
    private final JTextArea logArea = new JTextArea(18, 100);

    // Guarded by UI-thread usage; HttpBridgeServer is internally synchronized.
    private transient HttpBridgeServer server;

    public ConfigPanel(MontoyaApi api) {
        this.api = api;

        setLayout(new BorderLayout(8, 8));
        add(buildControls(), BorderLayout.NORTH);
        add(buildLog(), BorderLayout.CENTER);

        // Helpful one-time hints
        info("Endpoints: /health, /payloads, /interactions");
        info("Example: " + httpUrl(hostField.getText(), Integer.parseInt(portField.getText()), "/health"));
    }

    private JPanel buildControls() {
        // Fixed widths for Host (160px) and Port (80px) columns; buttons right-aligned.
        JPanel p = new JPanel(new MigLayout(
                "ins 8, fillx, wrap 6",
                "[left]8[160!,fill,grow 0]16[left]8[80!,fill,grow 0]push[right]",
                "[]"));
        p.setBorder(BorderFactory.createTitledBorder("Collaborator Bridge Controls"));

        p.add(new JLabel("Host:"));
        p.add(hostField, "growx 0");

        p.add(new JLabel("Port:"));
        p.add(portField, "growx 0");

        startButton.addActionListener(this::onStartClicked);
        stopButton.addActionListener(this::onStopClicked);
        p.add(startButton, "split 2, alignx right");
        p.add(stopButton, "alignx right");

        return p;
    }

    private JPanel buildLog() {
        JPanel p = new JPanel(new BorderLayout());
        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);
        scroll.setBorder(BorderFactory.createTitledBorder("Log"));
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    @SuppressWarnings("unused")
    private void onStartClicked(ActionEvent e) {
        startServer();
    }

    @SuppressWarnings("unused")
    private void onStopClicked(ActionEvent e) {
        stopServerSafely();
    }

    private void startServer() {
        final String host = hostField.getText().trim();
        final String ports = portField.getText().trim();

        final int port;
        try {
            port = Integer.parseInt(ports);
        } catch (NumberFormatException ex) {
            Logger.logError("Invalid port: " + ports + " (" + ex.getMessage() + ")");
            return;
        }

        if (server != null && server.isRunning()) {
            Logger.logInfo("Server already running on " + httpUrl(server.bindHost(), server.bindPort(), ""));
            return;
        }

        Logger.logInfo("Starting server on " + httpUrl(host, port, "") + " ...");

        new Thread(() -> {
            try {
                HttpBridgeServer s = new HttpBridgeServer(api, host, port);
                s.start();
                server = s;
                Logger.logInfo("Collaborator bridge started on " + httpUrl(host, port, ""));
            } catch (IllegalStateException _ ) {
                Logger.logError("Start failed: Collaborator disabled.");
            } catch (Exception ex) {
                Logger.logError("Start failed: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            }
        }, "collab-bridge-start").start();
    }

    public void stopServerSafely() {
        final HttpBridgeServer s = server;
        if (s == null || !s.isRunning()) {
            Logger.logInfo("Server not running.");
            return;
        }
        Logger.logInfo("Stopping server ...");
        new Thread(() -> {
            try {
                s.stop();
                Logger.logInfo("Stopped.");
            } catch (Exception ex) {
                Logger.logError("Stop error: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            } finally {
                server = null;
            }
        }, "collab-bridge-stop").start();
    }

    // ---- Logger.Sink ----
    @Override
    public void info(String msg) {
        appendToLog(msg);
    }

    @Override
    public void error(String msg) {
        appendToLog(msg);
    }

    private void appendToLog(String line) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(line + System.lineSeparator());
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    /** Builds an HTTP URL string for local use. */
    @SuppressWarnings("HttpUrlsUsage")
    private static String httpUrl(String host, int port, String path) {
        String p = (path == null) ? "" : path;
        return "http://" + host + ":" + port + p;
    }
}
