package ca.gosecure.cspauditor.gui;

import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import ca.gosecure.cspauditor.model.Directive;
import ca.gosecure.cspauditor.model.HeaderValidation;
import com.esotericsoftware.minlog.Log;
import org.apache.commons.io.IOUtils;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

public class CspHeadersPanel {


    private JPanel mainPanel = new JPanel();

    public CspHeadersPanel() {
        mainPanel.setLayout(new BorderLayout());
    }

    public Component getComponent() {
        return mainPanel;
    }

    private static final URL ICON_HIGH = getAccessibleResource("/resources/Media/scan_issue_high_certain_rpt.png");
    private static final URL ICON_MED  = getAccessibleResource("/resources/Media/scan_issue_medium_certain_rpt.png");
    private static final URL ICON_LOW  = getAccessibleResource("/resources/Media/scan_issue_decoration_info_certain.png");

    public void displayPolicy(java.util.List<ContentSecurityPolicy> p) {

        StringBuilder str = new StringBuilder();

        str.append("<html>");
        for(ContentSecurityPolicy policyOrig : p) {
            ContentSecurityPolicy policy = policyOrig.getComputedPolicy();
            str.append("<h1>Header : " + policy.getHeaderName() + "</h1>\n");

            for (Directive d : policy.getDirectives().values()) {
                str.append("<br/><nobr>&nbsp;&nbsp;<b>" + d.getName() + "</b> " + (d.isImplicit() ? "<i>(Implicit taken from the default-src)</i>" : "") + "</nobr><br/>\n");

                for (String value : d.getValues()) {
                    if (HeaderValidation.isAllowingAnyScript(d.getName(),value) ||
                            HeaderValidation.isAllowingInlineScript(d.getName(),value) ||
                            HeaderValidation.isAllowingUnsafeEvalScript(d.getName(),value) ||
                            HeaderValidation.isUserContentHost(d.getName(),value) ||
                            HeaderValidation.isHostingVulnerableJs(d.getName(),value)) {
                        str.append(iconify(value,ICON_HIGH,"red"));

                    } else if (HeaderValidation.isAllowingAnyStyle(d.getName(),value) ||
                            HeaderValidation.isAllowingAny(d.getName(),value)) {
                        str.append(iconify(value,ICON_MED,"orange"));

                    } else {
                        str.append(iconify(value,ICON_LOW,""));
                    }
                }
            }
        }
        str.append("<br/><br/></html>");

        JLabel lbl = new JLabel();
        lbl.setText(str.toString());


        mainPanel.removeAll();

        mainPanel.add(new JScrollPane(lbl));
    }

    private static String iconify(String message,URL icon,String color) {
        StringBuilder buffer = new StringBuilder("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;");
        buffer.append("<img height='14' width='14' src='file:///").append(icon ==null ? "":icon.getFile()).append("'>");
        buffer.append("&nbsp;<font title='blah' color='").append(color).append("'>");
        buffer.append(message);
        buffer.append("</font><br/>\n");
        return buffer.toString();
    }

    private static URL getAccessibleResource(String url) {

        URL urlResource = CspHeadersPanel.class.getResource(url);
        if(urlResource == null) {
            Log.error("Resource not found "+url);
        }
        if(!urlResource.getFile().contains(".jar!")) {
            return urlResource;
        }

        try {
            File tempFile = File.createTempFile("temp-file-name", ".png");

            System.out.println(tempFile.toPath());

            try (InputStream in = urlResource.openStream(); FileOutputStream out = new FileOutputStream(tempFile)) {
                IOUtils.copy(in, out);
            }
            return tempFile.toURI().toURL();
        }
        catch (IOException e) {
            Log.warn(e.getMessage());
            return null;
        }

    }
}
