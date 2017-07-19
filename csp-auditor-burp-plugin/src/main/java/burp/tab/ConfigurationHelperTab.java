package burp.tab;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITab;
import ca.gosecure.cspauditor.gui.generator.CspGeneratorPanel;
import ca.gosecure.cspauditor.gui.generator.CspGeneratorPanelController;

import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import ca.gosecure.cspauditor.model.generator.DetectInlineJavascript;
import com.esotericsoftware.minlog.Log;

/**
 * Tab that contains three parts :
 * - Configuration
 * - External Resources
 * - Inline Scripts
 */
public class ConfigurationHelperTab implements ITab, CspGeneratorPanelController {

    private CspGeneratorPanel panel;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private RequestResponsePanel resourceReqRespTab;
    private RequestResponsePanel inlineReqRespTab;

    public ConfigurationHelperTab(final IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        panel = new CspGeneratorPanel(this);

        resourceReqRespTab = new RequestResponsePanel(callbacks);
        panel.setResourceItem(resourceReqRespTab);
        inlineReqRespTab = new RequestResponsePanel(callbacks);
        panel.setInlineItem(inlineReqRespTab);
    }

    @Override
    public String getTabCaption() {
        return "CSP";
    }

    @Override
    public Component getUiComponent() {
        return panel.getRootPanel();
    }

    @Override
    public void analyzeDomain(String domain) {

        IHttpRequestResponse[] reqResponses = callbacks.getProxyHistory();


        ContentSecurityPolicy csp = new ContentSecurityPolicy("CSP");

        try {
            URL domainSelected = new URL(domain);

            panel.clearResources();
            panel.clearInlineScript();

            for (IHttpRequestResponse reqResp : reqResponses) {
                IRequestInfo reqInfo = helpers.analyzeRequest(reqResp.getHttpService(), reqResp.getRequest());
                if (reqResp.getResponse() == null) continue;
                IResponseInfo respInfo = helpers.analyzeResponse(reqResp.getResponse());

                String mimeType = respInfo.getInferredMimeType().toUpperCase(); //Uppercase is applied because to make the content-type uniform

                URL urlRequested = reqInfo.getUrl();
                String urlString = getUrl(reqInfo);
                String protoAndHost = urlRequested.getProtocol() + "://" + urlRequested.getHost();

                boolean isRequestToDomain = protoAndHost.equals(domain);

                //Finding inline script

                String host = getHeader("host", reqInfo.getHeaders());
                if (isRequestToDomain) {
                    if (mimeType.equals("HTML")) {
                        List<String> problemInline = DetectInlineJavascript.getInstance().findInlineJs(new String(reqResp.getResponse()));

                        for (String line : problemInline)
                            panel.addInlineScript(urlString, line);
                    }
                }


                //Finding external resources

                if (isRequestToDomain)
                    continue; //Same-Origin

                String referrer = getHeader("referer", reqInfo.getHeaders());
                if (referrer.startsWith("http://") || referrer.startsWith("https://")) {
                    URL referrerUrl = new URL(referrer);
                    if (domainSelected.getHost().equals(referrerUrl.getHost())) {
                        panel.addResource(urlString, mimeType);
                        mimeTypeToDirective(mimeType,protoAndHost,csp);

                    }
                }
            }
        } catch (MalformedURLException e) {

        }

        displayConfiguration(csp);
    }

    private void mimeTypeToDirective(String mimeType,String host,ContentSecurityPolicy csp) {

        String directive = null;
        switch (mimeType) {
            //case "HTML": return "frame-ancestors";
//            case "APPLET":
//            case "JAR":
//                return "object-src";
            case "CSS":
                directive = "style-src";
                break;
            case "PNG":
            case "JPG":
            case "JPEG":
            case "GIF":
                directive = "img-src";
                break;
            case "SCRIPT":
                directive = "script-src";
                break;
            case "FONT":
                directive = "font-src";
                break;
            case "WAV":
            case "MP3":
            case "MPG":
            case "MPEG":
            case "AVI":
                directive = "media-src";
                break;
        }

        if(directive != null) {
            csp.addDirectiveValue(directive, host);
        }

    }

    @Override
    public void refreshDomains() {

        Log.debug("Refreshing the domain list");
        IHttpRequestResponse[] reqResponses = callbacks.getProxyHistory();
        SortedSet<String> hosts = new TreeSet<>();
        for (IHttpRequestResponse reqResp : reqResponses) {
            IRequestInfo reqInfo = helpers.analyzeRequest(reqResp.getHttpService(), reqResp.getRequest());
            hosts.add(reqInfo.getUrl().getProtocol() + "://" + reqInfo.getUrl().getHost());
        }

//        for (String h : hosts) {
//            Log.debug(h);
//        }

        panel.addDomains(hosts);
    }

    @Override
    public void selectResource(String url) {
        displayReqResp(url, resourceReqRespTab);
    }

    @Override
    public void selectInline(String url) {
        inlineReqRespTab.selectResponse();
        displayReqResp(url, inlineReqRespTab);
    }

    private void displayReqResp(String url, RequestResponsePanel tabbedPane) {
        IHttpRequestResponse[] reqResponses = callbacks.getSiteMap(url);
        IHttpRequestResponse reqResp = null;
        for(IHttpRequestResponse rr : reqResponses) {
            reqResp = rr;
            if(rr.getResponse() != null) {
                break;
            }
        }
        if (reqResp != null) {

            tabbedPane.editorRequest.setMessage(reqResp.getRequest(), true);
            if (reqResp.getResponse() != null) tabbedPane.editorResponse.setMessage(reqResp.getResponse(), false);

        } else {
            Log.error("Oups request not found.");
        }
    }

    private void displayConfiguration(ContentSecurityPolicy policy) {

        IMessageEditor msg = callbacks.createMessageEditor(null, true);

        StringBuilder str = new StringBuilder();
        str.append("Content-Security-Policy: ");
        str.append(policy.toHeaderString());
        str.append("\n\n");

        msg.setMessage(str.toString().getBytes(), false);

        panel.setConfiguration(msg.getComponent());
    }

    private String getUrl(IRequestInfo reqInfo) {
        String url = reqInfo.getUrl().toString();

        try {//BUG: BurpSuite does not support default port being specified to getSiteMap() API
            URL urlTest = new URL(url); // Test if for port to remove from url
            if (urlTest.getDefaultPort() == urlTest.getPort()) {
                url = urlTest.getProtocol() + "://" + urlTest.getHost() + urlTest.getPath();
                if (urlTest.getQuery() != null) {
                    url += "?" + urlTest.getQuery();
                }
            }
        } catch (MalformedURLException e) {
        }

        return url;
    }

    private String getHeader(String name, List<String> headers) {
        for (String h : headers) {
            String[] parts = h.split(":", 2);
            String headerName = parts[0].trim();
            if (headerName.equalsIgnoreCase(name) && parts.length > 1) {
                return parts[1].trim();
            }
        }
        return "";
    }
}
