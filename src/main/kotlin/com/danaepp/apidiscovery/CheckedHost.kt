package com.danaepp.apidiscovery

import java.time.LocalDateTime

data class CheckedHost (
    var hostname: String = "",
    var apiMetadataDetected: Boolean = false,
    var apiMetadataURL: String = "",
    var apiMetadata: ApiJson? = null,
    var apiCatalogDetected: Boolean = false,
    var apiCatalogURL: String = "",
    var apiCatalogData: LinkSet? = null,
    var lastChecked: LocalDateTime = LocalDateTime.now()
)