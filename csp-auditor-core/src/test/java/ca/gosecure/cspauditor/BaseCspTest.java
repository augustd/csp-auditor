package ca.gosecure.cspauditor;

import java.util.HashMap;
import java.util.Map;

public class BaseCspTest {


    protected static Map<String,String> wrapInMap(String value) {
        Map<String,String> map = new HashMap<>();
        map.put("content-security-policy",value);
        return map;
    }
}
