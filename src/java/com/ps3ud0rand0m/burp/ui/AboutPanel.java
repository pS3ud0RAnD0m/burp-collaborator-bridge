package com.ps3ud0rand0m.burp.ui;

import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import java.io.Serial;

/**
 * Static information about the extension and its endpoints.
 */
public class AboutPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    public AboutPanel() {
        setLayout(new MigLayout("ins 12, fillx", "[grow,fill]", "[][grow]"));

        JTextArea info = new JTextArea();
        info.setEditable(false);
        info.setLineWrap(true);
        info.setWrapStyleWord(true);
        info.setText("""
            Burp Collaborator Bridge

            Purpose:
              Expose a minimal HTTP API inside Burp so external tools (e.g., Python scripts) can:
                - Generate Collaborator payloads
                - Retrieve interactions

            Endpoints:
              GET  /health
              GET  /payloads     (also accepts POST with JSON: {"custom":"<alnum<=16>", "without_server":"1"})
              GET  /interactions (filters: payload, id, since (ISO-8601 or epoch ms), types=dns,http,smtp, limit)

            Notes:
              - No authentication is currently enforced.
              - Bind address and port are set in the Config tab.
            """);
        info.setBorder(BorderFactory.createTitledBorder("About"));

        add(info, "grow");
    }
}
