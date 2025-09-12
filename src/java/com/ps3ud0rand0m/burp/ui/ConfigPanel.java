package com.ps3ud0rand0m.burp.ui;

import com.ps3ud0rand0m.burp.bridge.HttpBridgeServer;
import com.ps3ud0rand0m.burp.utils.Logger;
import burp.api.montoya.MontoyaApi;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
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
    private static final String MIG_ALIGN_LEFT = "alignx left";

    private final transient MontoyaApi api;

    private final JTextField hostField = new JTextField(DEFAULT_HOST, 16);
    private final JTextField portField = new JTextField(DEFAULT_PORT, 6);

    private final JButton startButton = new JButton("Start");
    private final JButton stopButton  = new JButton("Stop");

    // Running status indicator
    private final StatusDot statusDot = new StatusDot();
    private final JLabel statusLabel  = new JLabel("Stopped");

    // Unified log view
    private final JTextArea logArea = new JTextArea(18, 100);

    // Guarded by UI-thread usage; HttpBridgeServer is internally synchronized.
    private transient HttpBridgeServer server;

    public ConfigPanel(MontoyaApi api) {
        this.api = api;

        setLayout(new BorderLayout(8, 8));
        // Add top padding so the tab header doesn't crowd the titled border.
        setBorder(BorderFactory.createEmptyBorder(10, 8, 8, 8));

        add(buildControls(), BorderLayout.NORTH);
        add(buildLog(), BorderLayout.CENTER);

        setRunning(false);

        info("Endpoints: /health, /payloads, /interactions");
        info("Example: " + httpUrl(hostField.getText(), Integer.parseInt(portField.getText()), "/health"));
    }

    private JPanel buildControls() {
        // Columns: [Host label][Host field][Port label][Port field][Start][Stop][Dot][Text][spacer]
        JPanel p = new JPanel(new MigLayout(
                "ins 8, fillx, wrap 9",
                "[right]8[160!,fill,grow 0]16[right]8[80!,fill,grow 0]16[]8[]8[]8[]push",
                "[]"));
        p.setBorder(BorderFactory.createTitledBorder("Controls"));

        p.add(new JLabel("Host:"));
        p.add(hostField, "growx 0");

        p.add(new JLabel("Port:"));
        p.add(portField, "growx 0");

        startButton.addActionListener(this::onStartClicked);
        stopButton.addActionListener(this::onStopClicked);

        p.add(startButton, MIG_ALIGN_LEFT);
        p.add(stopButton, MIG_ALIGN_LEFT);

        p.add(statusDot, MIG_ALIGN_LEFT);
        p.add(statusLabel, MIG_ALIGN_LEFT);

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
            setRunning(true);
            return;
        }

        Logger.logInfo("Starting server on " + httpUrl(host, port, "") + " ...");
        setButtonsEnabled(false);

        new Thread(() -> {
            try {
                HttpBridgeServer s = new HttpBridgeServer(api, host, port);
                s.start();
                server = s;
                Logger.logInfo("Collaborator bridge started on " + httpUrl(host, port, ""));
                setRunning(true);
            } catch (IllegalStateException _ ) {
                Logger.logError("Start failed: Collaborator disabled.");
                setRunning(false);
            } catch (Exception ex) {
                Logger.logError("Start failed: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
                setRunning(false);
            } finally {
                setButtonsEnabled(true);
            }
        }, "collab-bridge-start").start();
    }

    public void stopServerSafely() {
        final HttpBridgeServer s = server;
        if (s == null || !s.isRunning()) {
            Logger.logInfo("Server not running.");
            setRunning(false);
            return;
        }

        Logger.logInfo("Stopping server ...");
        setButtonsEnabled(false);

        new Thread(() -> {
            try {
                s.stop();
                Logger.logInfo("Stopped.");
                setRunning(false);
            } catch (Exception ex) {
                Logger.logError("Stop error: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
                setRunning(false);
            } finally {
                server = null;
                setButtonsEnabled(true);
            }
        }, "collab-bridge-stop").start();
    }

    private void setButtonsEnabled(boolean enabled) {
        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(enabled);
            stopButton.setEnabled(enabled);
        });
    }

    private void setRunning(boolean running) {
        SwingUtilities.invokeLater(() -> {
            statusDot.setRunning(running);
            statusLabel.setText(running ? "Running" : "Stopped");
        });
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

    /** Circular status indicator. Green: running. Red: stopped. */
    private static final class StatusDot extends JComponent {
        @Serial private static final long serialVersionUID = 1L;

        // ~2x previous size
        private static final int DIAMETER = 24;

        private volatile boolean running;

        StatusDot() {
            setPreferredSize(new Dimension(DIAMETER + 6, DIAMETER + 6));
            setMinimumSize(getPreferredSize());
            setOpaque(false);
        }

        void setRunning(boolean running) {
            this.running = running;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int x = (getWidth() - DIAMETER) / 2;
                int y = (getHeight() - DIAMETER) / 2;
                g2.setColor(running ? new Color(0x2ECC71) : new Color(0xFF1700));
                g2.fillOval(x, y, DIAMETER, DIAMETER);
                g2.setColor(Color.DARK_GRAY);
                g2.drawOval(x, y, DIAMETER, DIAMETER);
            } finally {
                g2.dispose();
            }
        }
    }
}
