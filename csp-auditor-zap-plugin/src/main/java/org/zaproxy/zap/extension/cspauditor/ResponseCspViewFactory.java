package org.zaproxy.zap.extension.cspauditor;

import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.DefaultHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.view.HttpPanelManager;

public class ResponseCspViewFactory implements HttpPanelManager.HttpPanelViewFactory {

    public static final String NAME = ResponseCspViewFactory.class.getName();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public HttpPanelView getNewView() {
        return new ResponseCspView(new DefaultHttpPanelViewModel());
    }

    @Override
    public Object getOptions() {
        return ResponseSplitComponent.ViewComponent.BODY;
    }
}
