package ca.gosecure.cspauditor.gui.generator;

public interface CspGeneratorPanelController {

    void analyzeDomain(String domain);

    void refreshDomains();

    void selectResource(String id);

    void selectInline(String id);

    void selectReport(String id);
}
