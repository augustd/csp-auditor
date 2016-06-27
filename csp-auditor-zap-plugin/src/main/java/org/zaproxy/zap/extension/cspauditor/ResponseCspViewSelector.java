package org.zaproxy.zap.extension.cspauditor;

import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelDefaultViewSelector;

public class ResponseCspViewSelector implements HttpPanelDefaultViewSelector {

    public static final String NAME = ResponseCspViewSelector.class.getName();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public boolean matchToDefaultView(Message aMessage) {
        return ResponseCspView.hasCspHeader(aMessage);
    }

    @Override
    public String getViewName() {
        return ResponseCspView.NAME;
    }

    @Override
    public int getOrder() {
        return 30;
    }
}
