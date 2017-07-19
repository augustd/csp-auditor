package ca.gosecure.cspauditor.model.generator;

import ca.gosecure.cspauditor.util.SimpleListFile;
import com.esotericsoftware.minlog.Log;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DetectInlineJavascript {

    private Set<String> jsInlineEvents = new HashSet<>();

    private static DetectInlineJavascript instance = new DetectInlineJavascript();

    //Singleton pattern
    private DetectInlineJavascript() {}
    public static DetectInlineJavascript getInstance() { return instance; }

    private void preloadEvents() {
        if(jsInlineEvents.size() < 1) {
            try {
                SimpleListFile.openFile("/resources/data/js_inline_event.txt", (String line) -> {
                    jsInlineEvents.add(line);
                });
            } catch (IOException e) {
                Log.error("Unable to load the inline JS events" + e.getMessage(), e);
            }
        }
    }

    public List<String> findInlineJs(String source) {
        preloadEvents();
        String[] tokens = source.split("</");

        List<String> problematicLines = new ArrayList<>();

        for(String line : tokens) {
            if(line.contains(" on")) {
                for(String event : jsInlineEvents) {
                    if(line.contains(" "+event)) {

                        Pattern p = Pattern.compile(".{0,10} on" + event + ".{0,50}");
                        Matcher m = p.matcher(line);

                        if (m.find()) {
                            problematicLines.add(m.group(0));
                        }
                    }
                }
            }
            if(line.contains("<script")) {
                Pattern p = Pattern.compile("(<script[^>]*).{0,50}");
                Matcher m = p.matcher(line);
                if(m.find()) {
                    String scriptTag = m.group(1);
                    if(!scriptTag.contains("src="))
                        problematicLines.add(m.group(0));
                }
            }
        }

        return problematicLines;
    }
}
