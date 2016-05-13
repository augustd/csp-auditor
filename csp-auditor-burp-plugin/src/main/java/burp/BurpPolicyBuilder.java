package burp;

import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import ca.gosecure.cspauditor.util.PolicyBuilder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BurpPolicyBuilder extends PolicyBuilder {

    public static Map<String,String> getCspHeader(IResponseInfo response) {
        Map<String,String> headers = new HashMap<>();
        for(String header : response.getHeaders()) {
            String headerLower = header.toLowerCase();

            for(String cspHeader : CSP_HEADERS) {
                if (headerLower.startsWith(cspHeader)) {
                    String[] parts = header.split(":",2);
                    if(parts.length>1) {
                        headers.put(cspHeader, parts[1]);
                    }
                }
            }
        }
        return headers;
    }

    public static List<ContentSecurityPolicy> buildFromResponse(IResponseInfo responseInfo) {
        Map<String,String> headers = getCspHeader(responseInfo);
        return parseCspHeaders(headers);
    }
}
