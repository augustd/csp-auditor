package ca.gosecure.cspauditor.model;

import java.util.ArrayList;
import java.util.List;

public class HeaderValidation {

    public static boolean isAllowingAnyScript(String name, String value) {
        return (name.equals("script-src") || name.equals("object-src"))
                && (value.equals("*"));
    }

    public static boolean isAllowingInlineScript(String name, String value) {
        return (name.equals("script-src") || name.equals("object-src"))
                && (value.equals("'unsafe-inline'"));
    }
    public static boolean isAllowingUnsafeEvalScript(String name, String value) {
        return (name.equals("script-src") || name.equals("object-src"))
                && (value.equals("'unsafe-eval'"));
    }

    public static boolean isAllowingAny(String name, String value) {
        return value.equals("'unsafe-inline'") || value.equals("'unsafe-eval'") || value.equals("*");
    }

    public static boolean isAllowingAnyStyle(String name, String value) {
        return (name.equals("style-src") && value.equals("*"));
    }


    public static List<CspIssue> validateCspConfig(List<ContentSecurityPolicy> csp) {
        List<CspIssue> issues = new ArrayList<>();

        for(ContentSecurityPolicy policyOrig : csp) {
            ContentSecurityPolicy policy = policyOrig.getComputedPolicy();

            for (Directive d : policy.getDirectives().values()) {
                for (String value : d.getValues()) {
                    if (isAllowingAnyScript(d.getName(),value)) {
                        issues.add(new CspIssue(CspIssue.MED, "External scripts allowed", "issue_script_wildcard",  d));
                    } else if (isAllowingInlineScript(d.getName(),value)) {
                        issues.add(new CspIssue(CspIssue.MED, "Inline scripts can be inserted", "issue_script_unsafe_inline",d));
                    } else if (isAllowingUnsafeEvalScript(d.getName(),value)) {
                        issues.add(new CspIssue(CspIssue.MED, "Libraries using eval or setTimeout are allow", "issue_script_unsafe_eval",d));
                    } else if (isAllowingAnyStyle(d.getName(),value)) {
                        issues.add(new CspIssue(CspIssue.LOW, "External stylesheets allowed", "issue_style", d));
                    } else if (isAllowingAny(d.getName(),value)) {
                        issues.add(new CspIssue(CspIssue.INFO, "Use of wildcard", "issue_wildcard_limited", d));
                    }
                }
            }
        }

        return issues;
    }



}
