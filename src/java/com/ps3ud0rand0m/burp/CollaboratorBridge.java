package com.ps3ud0rand0m.burp;

import com.ps3ud0rand0m.burp.ui.CollaboratorBridgePanel;
import com.ps3ud0rand0m.burp.utils.Logger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Extension entry point: sets the name, initializes logging,
 * registers the suite tab, and ensures clean shutdown on unload.
 */
public class CollaboratorBridge implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        try {
            api.extension().setName("Collaborator Bridge");
            Logger.initialize(api.logging());

            CollaboratorBridgePanel panel = new CollaboratorBridgePanel(api);
            api.userInterface().registerSuiteTab("Collaborator Bridge", panel);

            try {
                api.extension().registerUnloadingHandler(panel::stopAllOnUnload);
            } catch (Throwable ignored) {
                // Older Montoya builds may not expose an unloading hook.
            }

            Logger.logInfo("Initialized successfully.");
        } catch (Exception e) {
            Logger.logError("Initialization failed: " + e.getMessage());
        }
    }
}
