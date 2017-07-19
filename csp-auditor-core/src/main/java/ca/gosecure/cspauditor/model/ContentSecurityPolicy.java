package ca.gosecure.cspauditor.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class ContentSecurityPolicy {

    private String headerName;
    private Map<String,Directive> directives = new LinkedHashMap<>();

    private Set<String> importantDirectives = new HashSet<>(Arrays.asList("script-src","object-src","style-src","img-src","media-src","frame-src","font-src","connect-src"));


    public ContentSecurityPolicy(String headerName) {
        this.headerName = headerName;
    }

    public void addDirective(Directive d)  {
        directives.put(d.getName(),d);
    }


    public String getHeaderName() {
        return headerName;
    }

    public Map<String, Directive> getDirectives() {
        return directives;
    }

    public ContentSecurityPolicy getComputedPolicy() {
        ContentSecurityPolicy pol = new ContentSecurityPolicy(headerName);

        Directive defaultSrc = directives.get("default-src");

        if(defaultSrc == null) {
            defaultSrc = new Directive("default-src", Arrays.asList("'self'"), true);
        }
        else {
            pol.addDirective(defaultSrc);
        }

        //Display the important first
        for(String directive : importantDirectives) {
            pol.addDirective(getDirectiveOrDefault(directive ,defaultSrc));
        }

        //Other directive found..
        for(String otherDirName : directives.keySet()) {
            if(!importantDirectives.contains(otherDirName)) {
                pol.addDirective(directives.get(otherDirName));
            }
        }

        return pol;
    }

    private Directive getDirectiveOrDefault(String name,Directive defaultSrc) {
        Directive targetDir = directives.get(name);
        return targetDir != null ? targetDir.clone(name) : defaultSrc.cloneImplicit(name);
    }

    public String toHeaderString() {
        StringBuilder str = new StringBuilder();
        for(String key : directives.keySet()) {
            str.append(key);
            Directive d = directives.get(key);
            for(String val : d.getValues()) {
                str.append(' ').append(val);
            }
            str.append("; ");
        }
        return str.toString();
    }

    public String toString() {
        StringBuilder str = new StringBuilder();

        ContentSecurityPolicy policy = getComputedPolicy();
        str.append("Header : "+policy.headerName+"\n");

        for(Directive d : policy.directives.values()) {
            str.append(d.getName()+""+(d.isImplicit()? " (Implicit)" : "")+"\n");
            for(String value : d.getValues()) {
                str.append("\t- "+value+"\n");
            }
        }
        return str.toString();
    }

    public void addDirectiveValue(String key, String domain) {
        Directive d = directives.get(key);
        if(d == null) {
            Directive newD = new Directive(key, new ArrayList<>());
            directives.put(key, newD);
            d = newD;
        }
        if(!d.getValues().contains(domain)) {
            d.getValues().add(domain);
        }
    }
}
