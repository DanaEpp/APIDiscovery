package com.danaepp.apidiscovery

import java.time.LocalDateTime

data class CheckedPath(
    var target: String = "",
    var apiDocPathDetected: Boolean = false,
    var detectedPaths: List<String>? = null,
    var lastChecked: LocalDateTime = LocalDateTime.now()
)
