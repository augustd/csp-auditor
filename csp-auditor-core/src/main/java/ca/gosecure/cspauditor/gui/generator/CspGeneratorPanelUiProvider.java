package ca.gosecure.cspauditor.gui.generator;

import java.awt.*;

public interface CspGeneratorPanelUiProvider {

    Component getTextEditor(byte[] content);

//    Component getRequestEditor(byte[] request,byte[] response);
}
