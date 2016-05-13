package ca.gosecure.cspauditor.util;

import ca.gosecure.cspauditor.model.Directive;
import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import com.esotericsoftware.minlog.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

public class PolicyBuilder {

    protected static List<String> CSP_HEADERS = Arrays.asList("x-content-security-policy", "x-webkit-csp", "content-security-policy");

    /**
     * Converted CSP header in the form of string to the object model.
     * @param headers Map of the CSP headers
     * @return
     */
    public static List<ContentSecurityPolicy> parseCspHeaders(Map<String,String> headers) {
        List<ContentSecurityPolicy> policies = new ArrayList<>();

        for (Map.Entry<String, String> header : headers.entrySet()) {
            ContentSecurityPolicy policy = new ContentSecurityPolicy(header.getKey());
            String[] headerParts = header.getValue().split(";");
            try {
                for (String part : headerParts) {
                    List<String> v = new ArrayList<>();
                    String trim = part.trim();
                    if(trim.equals("")) {
                        continue;
                    }
                    StringTokenizer tokenizer = new StringTokenizer(trim, " ");

                    String directiveName = tokenizer.nextToken();
                    while (tokenizer.hasMoreTokens()) {
                        String value = tokenizer.nextToken().trim();
                        if (!value.equals("")) v.add(value);
                    }
                    Directive d = new Directive(directiveName, v);

                    policy.addDirective(d);
                }

            }
            catch (NoSuchElementException e) {
                Log.error("Unexpected end of CSP directive: "+header.getValue());
            }

            policies.add(policy);
        }
        return policies;
    }
}
