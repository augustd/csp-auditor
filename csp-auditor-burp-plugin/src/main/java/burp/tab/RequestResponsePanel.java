package burp.tab;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;

import javax.swing.*;

public class RequestResponsePanel extends JTabbedPane {

    public IMessageEditor editorRequest;
    public IMessageEditor editorResponse;

    public RequestResponsePanel(IBurpExtenderCallbacks callbacks) {

        this.editorRequest = callbacks.createMessageEditor(null, false);
        this.editorResponse = callbacks.createMessageEditor(null, false);

        addTab("Request", editorRequest.getComponent());
        addTab("Response", editorResponse.getComponent());
    }

    public void selectResponse() {
        setSelectedIndex(1);
    }
}
