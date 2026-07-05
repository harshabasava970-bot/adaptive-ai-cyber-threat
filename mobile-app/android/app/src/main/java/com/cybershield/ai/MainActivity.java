package com.cybershield.ai;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

/**
 * MainActivity — CyberShield AI
 *
 * Extends Capacitor's BridgeActivity which hosts the WebView
 * that loads the mobile web app from assets/public/index.html.
 *
 * No backend logic lives here. All AI calls go to the FastAPI
 * endpoint at https://cyber-threat-api-4gms.onrender.com
 */
public class MainActivity extends BridgeActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}
