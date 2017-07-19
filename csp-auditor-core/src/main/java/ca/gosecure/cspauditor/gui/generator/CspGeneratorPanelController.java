package ca.gosecure.cspauditor.gui.generator;

public interface CspGeneratorPanelController {

    void analyzeDomain(String domain);

    void refreshDomains();

    void selectResource(String url);

    void selectInline(String url);
}
