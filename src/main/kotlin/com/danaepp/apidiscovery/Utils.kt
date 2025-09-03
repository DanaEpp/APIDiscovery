package com.danaepp.apidiscovery
import java.net.URI

class Utils {
    // Build a URI that tolerates funky paths
    public fun lenientUri(input: String): URI =
        runCatching { URI(input) }.getOrElse {
            // Split into scheme, authority, and the rest; then let URI do the encoding
            val parts = input.split("://", limit = 2)
            val scheme = parts.getOrNull(0)?.ifBlank { "http" } ?: "http"
            val rest   = parts.getOrNull(1) ?: ""
            val authority = rest.substringBefore("/").ifBlank { "localhost" }

            val afterAuth = rest.substringAfter("/", missingDelimiterValue = "")
            val pathPart  = afterAuth.substringBefore("?").substringBefore("#")
            val path      = if (pathPart.isEmpty()) null else "/$pathPart"

            val query     = afterAuth.substringAfter("?", "").substringBefore("#").ifBlank { null }

            // This constructor escapes illegal path chars (e.g., '[' -> %5B)
            URI(scheme, authority, path, query, null)
        }
}