package org.zaproxy.zap.extension.cspauditor;

import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import ca.gosecure.cspauditor.model.CspIssue;
import ca.gosecure.cspauditor.model.HeaderValidation;
import com.esotericsoftware.minlog.Log;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;

import java.util.List;

public class CspAuditorPassiveScanner extends PluginPassiveScanner {

    private static int PLUGIN_ID = 0x99991111;

    private static Logger logger = Logger.getLogger(CspAuditorPassiveScanner.class);


    private PassiveScanThread parent = null;


    public CspAuditorPassiveScanner() {
        Log.setLogger(new Log.Logger() {
            @Override
            public void log(int level, String category, String message, Throwable ex) {
                if(ex != null) {
                    logger.error(message,ex);
                }
                else {
                    logger.info(message);
                }
            }
        });
        Log.DEBUG();
    }

    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int i) {

    }

    @Override
    public void scanHttpResponseReceive(HttpMessage httpMessage, int refId, Source source) {
        List<ContentSecurityPolicy> csp = ZapPolicyBuilder.buildFromResponse(httpMessage);

        List<CspIssue> cspIssues = HeaderValidation.validateCspConfig(csp);

        convertIssues(cspIssues,httpMessage,refId);
    }

    private void convertIssues(List<CspIssue> cspIssues,HttpMessage message, int refId) {
        for(CspIssue issue : cspIssues) {
            Alert alert = new Alert(PLUGIN_ID, mapToZapSeverity(issue.getSeverity()), Alert.CONFIDENCE_HIGH, "CSP: "+issue.getTitle());
            alert.setDetail(stripHtmlTag(issue.getLocalizedMessage()),
                    message.getRequestHeader().getURI().toString(),
                    issue.getDirective() != null ? issue.getDirective().getName() : issue.getHighlightedValue(), //Param : CSP Directive or Header
                    "", //Attack
                    "", //Other info
                    "", //Solution
                    "", //One hyperlink
                    message
            );
            this.parent.raiseAlert(refId,alert);
        }

    }

    private String stripHtmlTag(String htmlMessage) {
        return htmlMessage.replaceAll("<[/]?b>","*")
                .replaceAll("<code>","[")
                .replaceAll("</code>","]")
                .replaceAll("<[/]?[a-z]+[/]?>","")
                .replaceAll("<a href=\"","").replaceAll("\">",": ")
                .replaceAll("&lt;","<").replaceAll("&gt;",">");
    }


    private int mapToZapSeverity(int severity) {
        if(severity == CspIssue.HIGH) {
            return Alert.RISK_HIGH;
        }
        else if (severity == CspIssue.MED) {
            return Alert.RISK_MEDIUM;
        }
        else if (severity == CspIssue.LOW) {
            return Alert.RISK_LOW;
        }
        return Alert.RISK_LOW;
    }

    @Override
    public void setParent(PassiveScanThread thread) {
        this.parent = thread;
    }

    @Override
    public String getName() {
        return "CSP Auditor";
    }
}
