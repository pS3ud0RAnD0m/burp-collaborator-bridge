package com.ps3ud0rand0m.burp.ui;

import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serial;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.vladsch.flexmark.ext.tables.TablesExtension;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.data.MutableDataSet;

public class AboutPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final String COPY_SCHEME = "copy://";
    private static final String LICENSE_SCHEME = "license://show";

    private final Map<String, String> copyPayloads = new LinkedHashMap<>();

    private final JTextArea licenseArea = new JTextArea(12, 80);
    private final JScrollPane licenseScroll = new JScrollPane(licenseArea);

    public AboutPanel() {
        setLayout(new MigLayout("ins 8, fill", "[grow,fill]", "[grow]8[]"));
        setBorder(BorderFactory.createEmptyBorder());

        String md = loadReadmeText();
        String html = renderMarkdown(md);
        html = rewriteLicenseLinkToLocal(html);
        html = injectInBlockCopyChip(html, copyPayloads);

        JEditorPane readmePane = buildReadmePane(html);
        JScrollPane readmeScroll = new JScrollPane(readmePane);
        readmeScroll.setBorder(BorderFactory.createEmptyBorder());
        readmeScroll.setViewportBorder(BorderFactory.createEmptyBorder());
        add(readmeScroll, "grow, wrap");

        licenseArea.setEditable(false);
        licenseArea.setLineWrap(true);
        licenseArea.setWrapStyleWord(true);
        licenseArea.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        licenseScroll.setBorder(BorderFactory.createEmptyBorder());
        licenseScroll.setViewportBorder(BorderFactory.createEmptyBorder());
        licenseScroll.setVisible(false);
        add(licenseScroll, "grow, hmin 0, hidemode 3");
    }

    private JEditorPane buildReadmePane(String html) {
        HTMLEditorKit kit = new HTMLEditorKit();
        StyleSheet css = kit.getStyleSheet();
        css.addRule("body { font-family: sans-serif; font-size: 12px; margin:0; }");
        css.addRule("h1 { font-size: 18px; margin: 10px 0 6px 0; }");
        css.addRule("h2 { font-size: 15px; margin: 10px 0 6px 0; }");
        css.addRule("p, li { line-height: 1.35; }");
        css.addRule("ul,ol { margin-left:18px; }");
        css.addRule("a { color:#6aa9ff; text-decoration:none; } a:hover { text-decoration:underline; }");

        css.addRule("pre { background:#202020; color:#ddd; padding:8px; border-radius:6px; margin:0; }");
        css.addRule("code { background:#2b2b2b; color:#ddd; padding:1px 3px; border-radius:3px; }");
        css.addRule("pre code { background:transparent; }");

        css.addRule("table.codewrap{ border-collapse:collapse; width:100%; margin:0 0 10px 0; }");
        css.addRule("td.precell{ padding:0; }");
        css.addRule("td.iconcell{ width:22px; vertical-align:top; background:#202020; border-top-right-radius:6px; }");

        css.addRule(".copychip{ display:inline-block; width:16px; height:16px; line-height:14px;" +
                " text-align:center; border:1px solid #6aa9ff; color:#6aa9ff; border-radius:3px;" +
                " background:transparent; margin:6px 6px 0 0; font-weight:bold; }");
        css.addRule(".copychip:hover{ background:#1e2a3a; }");

        JEditorPane pane = new JEditorPane();
        pane.setEditable(false);
        pane.setContentType("text/html");
        pane.setEditorKit(kit);
        pane.setText("<html><body>" + html + "</body></html>");
        pane.setBorder(BorderFactory.createEmptyBorder());
        pane.addHyperlinkListener(e -> {
            if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED) return;
            String url = e.getDescription();
            if (url == null) return;

            if (url.startsWith(COPY_SCHEME)) {
                String payload = copyPayloads.get(url);
                if (payload != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(payload), null);
                }
                return;
            }
            if (LICENSE_SCHEME.equals(url)) {
                toggleLicense();
                return;
            }
            if (url.startsWith("http://") || url.startsWith("https://")) {
                try { Desktop.getDesktop().browse(new URI(url)); } catch (Exception _ ) { /* noop */ }
            }
        });
        return pane;
    }

    private void toggleLicense() {
        if (!licenseScroll.isVisible()) {
            licenseArea.setText(loadLicenseText());
            licenseArea.setCaretPosition(0);
            licenseScroll.setVisible(true);
        } else {
            licenseScroll.setVisible(false);
        }
        revalidate();
        repaint();
    }

    private static String loadReadmeText() {
        String cp = readClasspath("/README.md");
        if (cp != null) return cp;
        String local = readLocal("README.md");
        if (local != null) return local;
        return "README.md not found.\n";
    }

    private static String loadLicenseText() {
        String cp = readClasspath("/LICENSE");
        if (cp != null) return cp;
        String local = readLocal("LICENSE");
        if (local != null) return local;
        return "LICENSE not found.\n";
    }

    private static String readClasspath(String path) {
        try (InputStream in = AboutPanel.class.getResourceAsStream(path)) {
            if (in == null) return null;
            return readAll(in);
        } catch (IOException e) {
            return "Error reading " + path + ": " + e.getMessage();
        }
    }

    private static String readLocal(String name) {
        try {
            Path p = Path.of(name);
            if (!Files.isRegularFile(p)) return null;
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "Error reading " + name + ": " + e.getMessage();
        }
    }

    private static String readAll(InputStream in) throws IOException {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder(8192);
            char[] buf = new char[4096];
            int n;
            while ((n = br.read(buf)) != -1) sb.append(buf, 0, n);
            return sb.toString();
        }
    }

    private static String renderMarkdown(String md) {
        MutableDataSet opts = new MutableDataSet();
        opts.set(Parser.EXTENSIONS, List.of(TablesExtension.create()));
        Parser parser = Parser.builder(opts).build();
        HtmlRenderer renderer = HtmlRenderer.builder(opts).build();
        return renderer.render(parser.parse(md));
    }

    private static String rewriteLicenseLinkToLocal(String html) {
        return html.replaceAll("href\\s*=\\s*([\"'])LICENSE\\1", "href=\"" + LICENSE_SCHEME + "\"");
    }

    private static String injectInBlockCopyChip(String html, Map<String, String> payloads) {
        Pattern p = Pattern.compile("<pre><code(?:\\s+class=\"[^\"]*\")?>(.*?)</code></pre>", Pattern.DOTALL);
        Matcher m = p.matcher(html);

        StringBuilder out = new StringBuilder(html.length() + 1024);
        int idx = 0;
        int last = 0;

        while (m.find()) {
            out.append(html, last, m.start());

            String codeHtml = m.group(1);
            String plain = htmlUnescape(codeHtml.replaceAll("<br\\s*/?>", "\n").replaceAll("</?[^>]+>", ""));
            String key = COPY_SCHEME + (idx++);
            payloads.put(key, plain);

            String table =
                    "<table class='codewrap'><tr>" +
                            "<td class='precell'><pre><code>" + codeHtml + "</code></pre></td>" +
                            "<td class='iconcell'><a href='" + key + "' class='copychip' title='Copy'>⧉</a></td>" +
                            "</tr></table>";

            out.append(table);
            last = m.end();
        }
        out.append(html, last, html.length());
        return out.toString();
    }

    private static String htmlUnescape(String s) {
        return s.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
                .replace("&quot;", "\"")
                .replace("&#39;", "'");
    }
}
