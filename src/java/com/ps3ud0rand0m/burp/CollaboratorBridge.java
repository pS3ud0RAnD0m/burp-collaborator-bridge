package com.ps3ud0rand0m.burp;

import com.ps3ud0rand0m.burp.ui.CollaboratorBridgePanel;
import com.ps3ud0rand0m.burp.utils.Logger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Entry point for the extension.
 * - Initializes Burp logging
 * - Registers the UI tab
 * - Ensures the panel can stop the server on unload
 */
public class CollaboratorBridge implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        try {
            api.extension().setName("Collaborator Bridge");
            Logger.initialize(api.logging());

            // Pass the MontoyaApi to the panel so it can manage the bridge.
            CollaboratorBridgePanel panel = new CollaboratorBridgePanel(api);
            api.userInterface().registerSuiteTab("Collaborator Bridge", panel);

            // Clean shutdown when the extension is unloaded.
            try {
                api.extension().registerUnloadingHandler(panel::stopServerSafely);
            } catch (Throwable ignored) {
                // If the API version lacks an unload hook, ignoring is fine.
            }

            Logger.logInfo("Initialized successfully.");
        } catch (Exception e) {
            Logger.logError("Initialization failed: " + e.getMessage());
        }
    }
}
