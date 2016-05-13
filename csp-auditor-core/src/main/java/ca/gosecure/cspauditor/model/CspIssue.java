package ca.gosecure.cspauditor.model;

import java.io.InputStream;

public class CspIssue {
    public static final int HIGH = 2;
    public static final int MED = 1;
    public static final int LOW = 0;
    public static final int INFO = -1;

    private final int severity;
    private final String title;
    private final String message;
    private final Directive directive;

    public CspIssue(int severity, String title, String message, Directive directive) {
        this.severity = severity;
        this.title = title;
        this.message = message;
        this.directive = directive;
    }

    public int getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getMessage() {
        return message;
    }

    public String getLocalizedMessage() {
        InputStream in = getClass().getResourceAsStream("/resources/descriptions/"+message);
        return convertStreamToString(in);
    }


    private static String convertStreamToString(InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    @Override
    public String toString() {
        String sev = severity == HIGH ? "High" :
                severity == MED? "Med" : "Low";
        return "[" + sev +"]\t" + message + "\t("+directive+")";
    }
}
