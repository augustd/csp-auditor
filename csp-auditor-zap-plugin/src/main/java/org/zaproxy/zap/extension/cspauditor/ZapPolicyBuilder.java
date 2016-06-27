package org.zaproxy.zap.extension.cspauditor;

import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import ca.gosecure.cspauditor.util.PolicyBuilder;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ZapPolicyBuilder extends PolicyBuilder {

    public static Map<String,String> getCspHeader(HttpMessage httpMessage) {
        Map<String,String> headers = new HashMap<>();

        for(HttpHeaderField header : httpMessage.getResponseHeader().getHeaders()) {
            String headerLower = header.getName().toLowerCase();

            for(String cspHeader : CSP_HEADERS) {
                if (headerLower.equals(cspHeader)) {
                    headers.put(header.getName(), header.getValue());
                }
            }
        }

        return headers;
    }

    public static List<ContentSecurityPolicy> buildFromResponse(HttpMessage httpMessage) {
        Map<String,String> headers = getCspHeader(httpMessage);
        return parseCspHeaders(headers);
    }
}
