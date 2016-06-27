package burp;

import ca.gosecure.cspauditor.gui.CspHeadersPanel;
import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import com.esotericsoftware.minlog.Log;

import java.awt.*;
import java.util.List;
import java.util.Map;

public class CspTab implements IMessageEditorTab {


    private byte[] message;

    private CspHeadersPanel cspHeaders;

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private IMessageEditorController controller;

    CspTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, IMessageEditorController controller) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.controller = controller;

        this.cspHeaders = new CspHeadersPanel();
    }

    @Override
    public String getTabCaption() {
        return "CSP";
    }

    @Override
    public Component getUiComponent() {
        return cspHeaders.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] respBytes, boolean isRequest) {
        if (isRequest) {
            return false;
        } else { //The tab will appears if it has at least one CSP header
            IResponseInfo responseInfo = helpers.analyzeResponse(respBytes);

            Map<String,String> cspHeaders = BurpPolicyBuilder.getCspHeader(responseInfo);
            return cspHeaders.size() > 0;
        }
    }

    @Override
    public void setMessage(byte[] respBytes, boolean isRequest) {
        this.message = respBytes;

        try {
            IResponseInfo responseInfo = helpers.analyzeResponse(respBytes);
            List<ContentSecurityPolicy> p = BurpPolicyBuilder.buildFromResponse(responseInfo);
            cspHeaders.displayPolicy(p);
        } catch (Exception e) {
            Log.error(e.getMessage());
        }
    }

    @Override
    public byte[] getMessage() {
        return message;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return message;
    }




}
