package org.zaproxy.zap.extension.cspauditor;

import ca.gosecure.cspauditor.gui.CspHeadersPanel;
import ca.gosecure.cspauditor.model.ContentSecurityPolicy;
import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelEvent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelListener;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Map;

public class ResponseCspView implements HttpPanelView, HttpPanelViewModelListener {

    public static final String NAME = ResponseCspView.class.getName();
    private HttpPanelViewModel model;

    private CspHeadersPanel propertyPanel;

    public ResponseCspView(HttpPanelViewModel model) {
        this.model = model;

        propertyPanel = new CspHeadersPanel();

        this.model.addHttpPanelViewModelListener(this);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getCaptionName() {
        return "CSP";
    }

    @Override
    public String getTargetViewName() {
        return "";
    }

    @Override
    public int getPosition() {
        return 3;
    }

    @Override
    public JComponent getPane() {
        return propertyPanel.getComponent();
    }

    @Override
    public void setSelected(boolean b) {

    }

    @Override
    public void save() {
    }

    @Override
    public HttpPanelViewModel getModel() {
        return model;
    }

    @Override
    public boolean isEnabled(Message message) {
        return hasCspHeader(message);
    }

    @Override
    public boolean hasChanged() {
        return false;
    }

    @Override
    public boolean isEditable() {
        return false;
    }

    @Override
    public void setEditable(boolean b) {
    }

    @Override
    public void setParentConfigurationKey(String s) {
    }

    @Override
    public void loadConfiguration(FileConfiguration fileConfiguration) {

    }

    @Override
    public void saveConfiguration(FileConfiguration fileConfiguration) {

    }

    static boolean hasCspHeader(final Message aMessage) {
        if(!(aMessage instanceof HttpMessage)) {
            return false;
        }
        HttpMessage httpMessage = (HttpMessage) aMessage;

        Map<String,String> headers = ZapPolicyBuilder.getCspHeader(httpMessage);
        return headers.size() > 0;
    }

    @Override
    public void dataChanged(HttpPanelViewModelEvent event) {
        HttpMessage httpMessage = (HttpMessage) model.getMessage();

        if (hasCspHeader(httpMessage)) {
            propertyPanel.displayPolicy(ZapPolicyBuilder.buildFromResponse(httpMessage));
        } else {
            propertyPanel.displayPolicy(new ArrayList<ContentSecurityPolicy>());
        }
    }
}
