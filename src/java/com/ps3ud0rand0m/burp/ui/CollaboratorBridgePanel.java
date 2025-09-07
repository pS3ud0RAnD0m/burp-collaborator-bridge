package com.ps3ud0rand0m.burp.ui;

import com.ps3ud0rand0m.burp.utils.Logger;
import burp.api.montoya.MontoyaApi;

import javax.swing.JTabbedPane;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.io.Serial;

/**
 * Container panel hosting subtabs: Config and About.
 * The Config tab itself mirrors all Logger output.
 */
public class CollaboratorBridgePanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private final ConfigPanel configPanel;
    private final AboutPanel aboutPanel;

    public CollaboratorBridgePanel(MontoyaApi api) {
        setLayout(new BorderLayout());

        configPanel = new ConfigPanel(api);
        // Mirror ALL Logger output into the Config tab.
        Logger.addSink(configPanel);

        aboutPanel = new AboutPanel();

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Config", configPanel);
        tabs.addTab("About", aboutPanel);

        add(tabs, BorderLayout.CENTER);
    }

    /** Called on extension unload for clean shutdown. */
    public void stopAllOnUnload() {
        try {
            configPanel.stopServerSafely();
        } finally {
            Logger.removeSink(configPanel);
        }
    }
}
