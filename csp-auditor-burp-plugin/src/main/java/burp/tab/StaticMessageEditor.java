package burp.tab;

import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

import java.awt.*;

public class StaticMessageEditor implements IMessageEditorController {
    private IHttpService iHttpService;
    private byte[] request;
    private byte[] response;

    public StaticMessageEditor(IHttpService iHttpService, byte[] request, byte[] response) {
        this.iHttpService = iHttpService;
        this.request = request;
        this.response = response;
    }

    @Override
    public IHttpService getHttpService() {
        return iHttpService;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }
}
