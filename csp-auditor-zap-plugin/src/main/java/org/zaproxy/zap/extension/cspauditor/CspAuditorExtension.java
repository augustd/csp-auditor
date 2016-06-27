package org.zaproxy.zap.extension.cspauditor;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.view.HttpPanelManager;

public class CspAuditorExtension extends ExtensionAdaptor {

  @Override
  public String getAuthor() {
    return "Philippe Arteau";
  }

  @Override
  public void hook(ExtensionHook extensionHook) {

    if (getView() != null) {
      HttpPanelManager panelManager = HttpPanelManager.getInstance();
      panelManager.addResponseViewFactory(ResponseSplitComponent.NAME, new ResponseCspViewFactory());
      panelManager.addResponseDefaultViewSelectorFactory(ResponseSplitComponent.NAME, new ResponseImageMetadataViewSelectorFactory());
    }
  }

  @Override
  public void unload() {
    if (getView() != null) {
      HttpPanelManager panelManager = HttpPanelManager.getInstance();
      panelManager.removeResponseViewFactory(ResponseSplitComponent.NAME,
              ResponseCspViewFactory.NAME);
      panelManager.removeResponseViews(
              ResponseSplitComponent.NAME,
              ResponseCspView.NAME,
              ResponseSplitComponent.ViewComponent.BODY);

      panelManager.removeResponseDefaultViewSelectorFactory(
              ResponseSplitComponent.NAME,
              ResponseCspViewFactory.NAME);
      panelManager.removeResponseDefaultViewSelectors(ResponseSplitComponent.NAME,
              ResponseCspViewSelector.NAME,
              ResponseSplitComponent.ViewComponent.BODY);
    }
  }
}
