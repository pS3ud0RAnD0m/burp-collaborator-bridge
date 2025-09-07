package com.ps3ud0rand0m.burp.ui;

import com.ps3ud0rand0m.burp.utils.Logger;

import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.io.Serial;

/**
 * Simple log view for runtime messages.
 * Implements Logger.Sink so it mirrors all Logger output automatically.
 */
public class LogPanel extends JPanel implements Logger.Sink {

    @Serial
    private static final long serialVersionUID = 1L;

    private final JTextArea logArea = new JTextArea(18, 100);

    public LogPanel() {
        setLayout(new BorderLayout(8, 8));

        JPanel top = new JPanel(new MigLayout("ins 8, fillx", "push[right]"));
        JButton clear = new JButton("Clear");
        clear.addActionListener(this::onClearClicked);
        top.add(clear, "alignx right");
        add(top, BorderLayout.NORTH);

        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);
        scroll.setBorder(BorderFactory.createTitledBorder("Log Output"));
        add(scroll, BorderLayout.CENTER);
    }

    public void append(String line) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(line + System.lineSeparator());
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    @SuppressWarnings("unused")
    private void onClearClicked(ActionEvent ignored) {
        clear();
    }

    private void clear() {
        SwingUtilities.invokeLater(() -> logArea.setText(""));
    }

    // ---- Logger.Sink ----
    @Override
    public void info(String msg) {
        append(msg);
    }

    @Override
    public void error(String msg) {
        append(msg);
    }
}
