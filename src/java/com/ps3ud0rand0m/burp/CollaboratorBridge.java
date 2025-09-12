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

            // Some Montoya builds may not expose an unloading hook; register if available.
            safeRegisterUnload(api, panel);

            Logger.logInfo("Initialized successfully.");
        } catch (Exception e) {
            Logger.logError("Initialization failed: " + e.getMessage());
        }
    }

    /** Attempt to register an unload handler; ignore if the API is not available on this build. */
    private static void safeRegisterUnload(MontoyaApi api, CollaboratorBridgePanel panel) {
        try {
            api.extension().registerUnloadingHandler(panel::stopAllOnUnload);
        } catch (Exception _) {
            // Unloading hook not supported; nothing to do.
        }
    }
}
