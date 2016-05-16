package ca.gosecure.cspauditor.model;

import com.esotericsoftware.minlog.Log;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

public class WeakCdnHostTest {

    @Test
    public void loadingBlacklistUserContentHosts() {
        Log.DEBUG();

        WeakCdnHost wch = WeakCdnHost.getInstance();

        System.out.println(wch.getBlacklistUserContentHosts().size() + " hosts allowing user content to be uploaded.");

        for(String host : wch.getBlacklistUserContentHosts()) {
            System.out.println(host);
        }
    }

    @Test
    public void loadingBlacklistVulnerableJsHosts() {
        Log.DEBUG();

        WeakCdnHost wch = WeakCdnHost.getInstance();

        System.out.println(wch.getBlacklistVulnerableJsHosts().size() + " hosts with vulnerable JavaScript");

        for(String host : wch.getBlacklistVulnerableJsHosts()) {
            System.out.println(host);
        }
    }

    @Test
    public void findGoogleApis() {
        WeakCdnHost wch = WeakCdnHost.getInstance();

        //Testing a couple of variations
        assertTrue(wch.isHostingVulnerableJs("*.googleapis.com"));
        assertTrue(wch.isHostingVulnerableJs("ajax.googleapis.com"));
        assertTrue(wch.isHostingVulnerableJs("ajax.googleapis.com/ajax/libs/"));
        assertTrue(wch.isHostingVulnerableJs("ajax.googleapis.com/ajax/"));
        assertTrue(wch.isHostingVulnerableJs("ajax.googleapis.com/"));
    }
}
