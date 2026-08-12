package com.webbinroot.ocisigner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.webbinroot.ocisigner.auth.OciConfigProfileResolver;
import com.webbinroot.ocisigner.auth.OciCrypto;
import com.webbinroot.ocisigner.auth.OciRpstSessionManager;
import com.webbinroot.ocisigner.auth.OciX509SessionManager;
import com.webbinroot.ocisigner.keys.OciPrivateKeyCache;
import com.webbinroot.ocisigner.util.OciDebug;
import com.webbinroot.ocisigner.signing.OciRequestSigner;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.ProfileStore;
import com.webbinroot.ocisigner.ui.OciSignerTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Burp entrypoint for OCISigner.
 *
 * Example flow:
 *  - Input request:  GET /n/  (Host: objectstorage.<region>.oraclecloud.com)
 *  - Output request: Authorization + Date headers added before sending
 */
public class OciSignerExtension implements BurpExtension {

    private ProfileStore store;

    @SuppressWarnings("unused")
    private Registration httpHandlerReg;

    @SuppressWarnings("unused")
    private Registration contextMenuReg;

    @SuppressWarnings("unused")
    private Registration unloadingHandlerReg;

    @Override
    public void initialize(MontoyaApi api) {
        // Example: registers "OCISigner" tab and HTTP handler for signing.
        // Name shown in Burp's Extensions list + tab title.
        api.extension().setName("OCISigner");

        // Route internal logs to Burp Output tab (instead of stdout).
        OciDebug.setLogger(api.logging()::logToOutput);

        // Create profile store (Profile1 default).
        store = new ProfileStore();
        // Apply current log level to debug logger.
        OciDebug.setLevel(store.logLevel());

        // Keep debug level in sync with UI selection.
        store.registerListener(msg -> {
            if (msg != null && msg.contains("global_log_level")) {
                OciDebug.setLevel(store.logLevel());
            }
        });

        // UI
        OciSignerTab tab = new OciSignerTab(api, store);
        // Register the tab in Burp UI.
        api.userInterface().registerSuiteTab("OCISigner", tab.getRoot());

        // HTTP handler (sign & forward)
        httpHandlerReg = api.http().registerHttpHandler(new HttpHandler() {

            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                // Return original request when signing is disabled, profile not chosen,
                // or target not in scope (if scope-only enabled).
                if (!store.signingEnabled()) {
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }

                if (requestToBeSent.toolSource().isFromTool(ToolType.EXTENSIONS)) {
                    // Our own Test Credentials probe (ProfileConfigurationPanel) already
                    // signs itself via a direct OciRequestSigner.sign() call before handing
                    // off to api.http().sendRequest() -- letting it re-enter here would
                    // sign it a second time, the same double-signing bug class as the
                    // removed ProxyRequestHandler registration above.
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }

                HttpRequest signed = signIfEnabled(api, requestToBeSent, requestToBeSent.isInScope());
                return RequestToBeSentAction.continueWith(signed);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                // No response modification.
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        // NOTE: no separate api.proxy().registerRequestHandler() here. Montoya's
        // generic HttpHandler (registered above) already fires for "requests made by
        // any Burp tool", Proxy included -- registering both handlers signed every
        // Proxy-sourced request twice (the first pass's work was fully discarded when
        // the second pass re-signed over its own already-added Authorization header).

        // Right-click context menu
        contextMenuReg = api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                // Build a dynamic right-click menu each time.
                List<Component> items = new ArrayList<>();

                JMenu root = new JMenu("OCISigner");

                // Signing submenu (Enabled/Disabled as two distinct options)
                JMenu signingMenu = new JMenu("Signing");

                JRadioButtonMenuItem enabled = new JRadioButtonMenuItem("Signing Enabled", store.signingEnabled());
                JRadioButtonMenuItem disabled = new JRadioButtonMenuItem("Signing Disabled", !store.signingEnabled());

                ButtonGroup g = new ButtonGroup();
                g.add(enabled);
                g.add(disabled);

                // Wire actions to toggle global signing on/off.
                enabled.addActionListener(e -> store.setSigningEnabled(true));
                disabled.addActionListener(e -> store.setSigningEnabled(false));

                signingMenu.add(enabled);
                signingMenu.add(disabled);

                root.add(signingMenu);

                JMenu always = new JMenu("Always Sign With");

                JMenuItem none = new JMenuItem("No Profile");
                none.addActionListener(e -> store.setAlwaysSignWith(null));
                always.add(none);
                always.addSeparator();

                // Add one menu item per profile.
                for (Profile p : store.all()) {
                    JMenuItem mi = new JMenuItem(p.name());
                    mi.addActionListener(e -> store.setAlwaysSignWith(p));
                    always.add(mi);
                }

                root.add(always);
                items.add(root);
                return items;
            }
        });

        // Release in-memory credential caches (private keys, session tokens, RequestSigners,
        // pooled federation HttpClients) when the extension unloads, rather than leaving
        // decrypted key material sitting in static caches until Burp itself exits.
        unloadingHandlerReg = api.extension().registerUnloadingHandler(() -> {
            OciX509SessionManager.clear();
            OciRpstSessionManager.clear();
            OciCrypto.clear();
            OciPrivateKeyCache.clear();
            OciConfigProfileResolver.clear();
            api.logging().logToOutput("[OCI Signer] Unloaded; credential caches cleared.");
        });

        // Startup log (no disk access).
        api.logging().logToOutput("[OCI Signer] Loaded.");
    }

    private HttpRequest signIfEnabled(MontoyaApi api, HttpRequest request, boolean inScope) {
        if (request == null) return null;
        if (store == null) return request;
        if (!store.signingEnabled()) {
            api.logging().logToOutput("[OCI Signer] Skipped (global signing disabled)");
            return request;
        }

        Profile p = store.alwaysSignWith();
        if (p == null) {
            api.logging().logToOutput("[OCI Signer] Skipped (no profile selected in Always Sign With)");
            return request;
        }

        if (p.onlyInScope && !inScope) {
            api.logging().logToOutput("[OCI Signer] Skipped (request not in Burp target scope)");
            return request;
        }

        try {
            String lvl = store.logLevel();
            boolean debug = "Debug".equalsIgnoreCase(lvl);
            boolean info = !"Error".equalsIgnoreCase(lvl);

            java.util.function.Consumer<String> infoLog =
                    info ? api.logging()::logToOutput : null;
            java.util.function.Consumer<String> errorLog =
                    api.logging()::logToError;

            return OciRequestSigner.sign(
                    request,
                    p,
                    infoLog,
                    errorLog,
                    debug
            );
        } catch (Exception ex) {
            api.logging().logToError("[OCI Signer] Handler exception: " + ex);
            return request;
        }
    }
}
