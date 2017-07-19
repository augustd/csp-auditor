package ca.gosecure.cspauditor.model;

import ca.gosecure.cspauditor.util.SimpleListFile;
import com.esotericsoftware.minlog.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class WeakCdnHost {

    private Boolean blacklistLoaded = false;

    private static final String USER_CONTENT_HOSTS_PATH = "/resources/data/csp_host_user_content.txt";
    private static final String VULNERABLE_JS_HOSTS_PATH = "/resources/data/csp_host_vulnerable_js.txt";

    private Set<String> blacklistUserContentHosts = new HashSet<>();
    private Set<String> blacklistVulnerableJsHosts = new HashSet<>();

    private static WeakCdnHost instance = new WeakCdnHost();

    //Singleton pattern
    private WeakCdnHost() {}
    public static WeakCdnHost getInstance() { return instance; }


    private void preloadLists() {
        if(!blacklistLoaded) { //Race-conditions will at worst load two times the list.
            blacklistLoaded = true;

            try {
                loadFileToSet(USER_CONTENT_HOSTS_PATH,  blacklistUserContentHosts);
                loadFileToSet(VULNERABLE_JS_HOSTS_PATH, blacklistVulnerableJsHosts);
            } catch (IOException e) {
                Log.error("Unable to load the blacklist hosts :"+ e.getMessage(),e);
            }
        }
    }

    private void loadFileToSet(String file,Set<String> set) throws IOException {
        Log.debug("Loading file : "+file);

        SimpleListFile.openFile(file, (String line) -> {

            //Adding precise main
            set.add(line);

            //Adding subpath
            String subPath = line;
            int lastIndex = -1;
            while((lastIndex = subPath.lastIndexOf("/")) != -1) {
                subPath = subPath.substring(0, lastIndex+1);
                set.add(subPath);
//                System.out.println(subPath);
                subPath = subPath.substring(0, subPath.length()-1); //Remove the trailing slash
            }

        });

        //Add wildcard on subdomain

        Iterator<String> it = set.iterator();
        Set<String> wildcardsVariations = new HashSet<>();
        while(it.hasNext()) {
            String url = it.next();

            String subDomain = url;

            int firstIndex = -1;
            while((firstIndex = subDomain.indexOf(".")) != -1) {
                subDomain = subDomain.substring(firstIndex+1,subDomain.length());
                wildcardsVariations.add("*."+subDomain);
                //System.out.println(subDomain);
            }
        }

        set.addAll(wildcardsVariations);

    }

    public boolean isUserContentHost(String value) {
        preloadLists();
        return blacklistUserContentHosts.contains(value) ||  blacklistUserContentHosts.contains(value+"/");
    }


    public boolean isHostingVulnerableJs(String value) {
        preloadLists();
        return blacklistVulnerableJsHosts.contains(value) || blacklistVulnerableJsHosts.contains(value+"/");
    }

    public Set<String> getBlacklistVulnerableJsHosts() {
        preloadLists();
        return blacklistVulnerableJsHosts;
    }
    public Set<String> getBlacklistUserContentHosts() {
        preloadLists();
        return blacklistUserContentHosts;
    }
}
