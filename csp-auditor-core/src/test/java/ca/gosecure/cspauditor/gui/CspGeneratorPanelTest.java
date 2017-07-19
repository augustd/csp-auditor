package ca.gosecure.cspauditor.gui;

import ca.gosecure.cspauditor.gui.generator.CspGeneratorPanel;
import ca.gosecure.cspauditor.gui.generator.CspGeneratorPanelController;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;

public class CspGeneratorPanelTest {
    public static void main(String[] args) {

        JFrame frame = new JFrame("Testing frame");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);


        CspGeneratorPanel panel = new CspGeneratorPanel(new CspGeneratorPanelController() {
            @Override
            public void analyzeDomain(String domain) {

            }

            @Override
            public void refreshDomains() {

            }

            @Override
            public void selectResource(String path) {

            }

            @Override
            public void selectInline(String url) {

            }
        });

        panel.addDomains(Arrays.asList("facebook.com","shopify.com","yahoo.ca"));

        panel.setConfiguration(new JTextArea("default-src 'self'; script-src 'self' www.google-analytics.com ssl.google-analytics.com; style-src 'self' 'unsafe-inline'; img-src 'self' www.google-analytics.com ssl.google-analytics.com; object-src 'none'; media-src 'none'; frame-src 'none'"));

        panel.addResource("AAAAAAAAAAAAAAA","SHOULD NOT BE VISIBLE");
        panel.clearResources();
        panel.addResource("<img src='xxx' onerror='aaaaa'>","/conferences/?test=1b&test=1");
        panel.addResource("<body onload='aaaaa'>","/index?test=1b&test=1");

        panel.setResourceItem(new JTextArea("<img src='xxx' onerror='aaaaa'>"));

        frame.add(panel.getRootPanel());
        frame.pack();
        frame.setMinimumSize(new Dimension(600,400));
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }
}
