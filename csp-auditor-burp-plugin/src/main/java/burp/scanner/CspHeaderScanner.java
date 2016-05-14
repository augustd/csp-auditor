package burp.scanner;

import burp.BurpPolicyBuilder;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import ca.gosecure.cspauditor.model.CspIssue;
import ca.gosecure.cspauditor.model.HeaderValidation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CspHeaderScanner implements IScannerCheck {

    private IExtensionHelpers helpers;

    public CspHeaderScanner(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
//        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse.getRequest());
        IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());

        List<ContentSecurityPolicy> csp = BurpPolicyBuilder.buildFromResponse(responseInfo);

        List<CspIssue> cspIssues = HeaderValidation.validateCspConfig(csp);

        if(cspIssues.size() == 0)
            return new ArrayList<IScanIssue>();

        return convertIssues(cspIssues,baseRequestResponse);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null; //No active scanning done
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    private List<IScanIssue> convertIssues(List<CspIssue> issues,IHttpRequestResponse baseRequestResponse) {

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());

        List<IScanIssue> burpIssues = new ArrayList<>();
        Set<String> types = new HashSet<>(); //Avoid issuing multiples alert for the same type.
        for(CspIssue i : issues) {
            if(!types.contains(i.getMessage())) {
                types.add(i.getMessage());

                String name = "CSP: "+i.getTitle();
                String detail = i.getLocalizedMessage();
                String severity;
                //See IScanIssue.getSeverity() doc for more info
                if(i.getSeverity() == CspIssue.HIGH) {
                    severity = "High";
                }
                else if(i.getSeverity() == CspIssue.MED) {
                    severity = "Medium";
                }
                else if(i.getSeverity() == CspIssue.LOW) {
                    severity = "Low";
                }
                else {
                    continue;
                }
                String confidence = "Firm";

                ;
                burpIssues.add(new BurpCspIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),new MockHttpRequestResponse(baseRequestResponse,i.getHighlightedValue()),
                        name,detail,severity,confidence));
            }
        }
        return burpIssues;
    }
}
