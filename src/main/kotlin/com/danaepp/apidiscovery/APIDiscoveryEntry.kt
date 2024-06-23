package com.danaepp.apidiscovery

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

@Suppress("unused")
class APIDiscoveryEntry : BurpExtension {
    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }

        api.extension().setName("API Discovery")
        api.scanner().registerScanCheck(APIDiscoveryScanCheck(api));
        api.logging().logToOutput("Loaded API Discovery extension")

    }
}