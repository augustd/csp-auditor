package ca.gosecure.cspauditor.util;

import burp.IResponseInfo;
import ca.gosecure.cspauditor.model.Directive;
import ca.gosecure.cspauditor.model.ContentSecurityPolicy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

public class PolicyBuilder {
    private static List<String> CSP_HEADERS = Arrays.asList("x-content-security-policy", "x-webkit-csp", "content-security-policy");

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

    public static List<ContentSecurityPolicy> parseCspHeaders(Map<String,String> headers) {
        List<ContentSecurityPolicy> policies = new ArrayList<>();

        for(Map.Entry<String,String> header : headers.entrySet()) {
            ContentSecurityPolicy policy = new ContentSecurityPolicy(header.getKey());
            String[] headerParts = header.getValue().split(";");
            for(String part : headerParts) {
                List<String> v = new ArrayList<>();
                StringTokenizer tokenizer = new StringTokenizer(part.trim()," ");

                String directiveName = tokenizer.nextToken();
                while(tokenizer.hasMoreTokens()) {
                    String value = tokenizer.nextToken().trim();
                    if(!value.equals("")) v.add(value);
                }
                Directive d = new Directive(directiveName, v);

                policy.addDirective(d);
            }

            policies.add(policy);
        }
        return policies;
    }
}
