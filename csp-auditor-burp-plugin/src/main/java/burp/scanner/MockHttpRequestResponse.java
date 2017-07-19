package burp.scanner;

import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;

import java.util.ArrayList;
import java.util.List;

public class MockHttpRequestResponse implements IHttpRequestResponseWithMarkers {

    IHttpRequestResponse actual;
    List<int[]> responseMarkers = new ArrayList<>();

    MockHttpRequestResponse(IHttpRequestResponse actual, String... highlightedValues) {
        byte[] responseBytes = actual.getResponse();
        for(String value : highlightedValues) {
            int startIndex = indexOf(responseBytes,value.getBytes());
            if(startIndex != -1) {
                int endIndex = value.length();
                responseMarkers.add(new int[] {startIndex,startIndex+endIndex});
            }
        }
        this.actual = actual;
    }

    @Override
    public byte[] getRequest() {
        return actual.getRequest();
    }

    @Override
    public void setRequest(byte[] message) {
        actual.setRequest(message);
    }

    @Override
    public byte[] getResponse() {
        return actual.getResponse();
    }

    @Override
    public void setResponse(byte[] message) {
        actual.setResponse(message);
    }

    @Override
    public String getComment() {
        return actual.getComment();
    }

    @Override
    public void setComment(String comment) {
        actual.setComment(comment);
    }

    @Override
    public String getHighlight() {
        return actual.getHighlight();
    }

    @Override
    public void setHighlight(String color) {
        actual.setHighlight(color);
    }

    @Override
    public IHttpService getHttpService() {
        return actual.getHttpService();
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        actual.setHttpService(httpService);
    }

    @Override
    public List<int[]> getRequestMarkers() {
        return null;
    }

    @Override
    public List<int[]> getResponseMarkers() {
        return responseMarkers;
    }


    public int indexOf(byte[] outerArray, byte[] smallerArray) {
        for(int i = 0; i < outerArray.length - smallerArray.length+1; ++i) {
            boolean found = true;
            for(int j = 0; j < smallerArray.length; ++j) {
                if (outerArray[i+j] != smallerArray[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }
}
