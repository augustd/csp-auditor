package ca.gosecure.cspauditor.model;

import ca.gosecure.cspauditor.BaseCspTest;
import ca.gosecure.cspauditor.util.PolicyBuilder;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.fail;

public class HeaderValidationTest extends BaseCspTest {

    private static String CSP_ALLOW_ALL = "default-src: *";

    @Test
    public void findUnsafeEval() {
        List<ContentSecurityPolicy> p = PolicyBuilder.parseCspHeaders(wrapInMap("script-src 'unsafe-eval'"));
        List<CspIssue> issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_unsafe_eval");


        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src 'unsafe-inline'; script-src 'unsafe-eval'"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_unsafe_eval");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src *; script-src 'unsafe-eval'"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_unsafe_eval");


        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src self; script-src 'unsafe-eval'"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_unsafe_eval");
    }

    @Test
    public void findUnsafeInline() {
        List<ContentSecurityPolicy> p = PolicyBuilder.parseCspHeaders(wrapInMap("script-src 'unsafe-inline'"));
        List<CspIssue> issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_unsafe_inline");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src 'unsafe-inline'"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_unsafe_inline");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src self, xss.lol ; script-src 'unsafe-inline'"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_unsafe_inline");
    }

    @Test
    public void findScriptWildCard() {
        List<ContentSecurityPolicy> p = PolicyBuilder.parseCspHeaders(wrapInMap(""));
        List<CspIssue> issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_wildcard");


        p = PolicyBuilder.parseCspHeaders(wrapInMap("script-src *"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_wildcard");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src self; script-src *"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_wildcard");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src self, xss.lol ; script-src *"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_script_wildcard");
    }

    @Test
    public void findUnsafeStyle() {
        List<ContentSecurityPolicy> p = PolicyBuilder.parseCspHeaders(wrapInMap(""));
        List<CspIssue> issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_style");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src self; style-src *"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_style");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src *"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_style");
    }

    @Test
    public void findWildcardLowRisk() {
        List<ContentSecurityPolicy> p = PolicyBuilder.parseCspHeaders(wrapInMap(""));
        List<CspIssue> issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_wildcard_limited");

        p = PolicyBuilder.parseCspHeaders(wrapInMap("default-src self; media-src *"));
        issues = HeaderValidation.validateCspConfig(p);
        System.out.println(p);
        hasIssueType(issues, "issue_wildcard_limited");
    }


    private void hasIssueType(List<CspIssue> issues, String msg) {
        System.out.println(issues.size() + " found");
        boolean issueFound = false;
        for(CspIssue issue: issues) {
            System.out.println(" - "+issue);
            if(issue.getMessage().equals(msg)) {
                issueFound = true;
            }
        }
        if(!issueFound) fail("Unable to find the issue of the type "+msg);
    }
}
