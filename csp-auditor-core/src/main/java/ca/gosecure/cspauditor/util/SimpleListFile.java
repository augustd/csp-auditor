package ca.gosecure.cspauditor.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.function.Consumer;

public class SimpleListFile {

    public static void openFile(String file, Consumer<String> consumer) throws IOException {
        InputStream in = SimpleListFile.class.getResourceAsStream(file);

        BufferedReader r1 = new BufferedReader(new InputStreamReader(in));
        String line;
        while((line = r1.readLine()) != null) {

            //Remove comment
            int indexComment = line.indexOf("#");
            if (indexComment != -1) {
                line = line.substring(0, indexComment);
            }
            line = line.trim();

            if ("".equals(line)) {
                continue;
            }
            consumer.accept(line);
        }
    }
}
