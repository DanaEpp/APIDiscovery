package com.danaepp.apidiscovery

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.AuditResult.auditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import java.net.URI
import java.time.LocalDateTime
import kotlinx.coroutines.runBlocking

class APIDiscoveryScanCheck( private val api: MontoyaApi ): ScanCheck {

    private val checkedHosts = mutableListOf<CheckedHost>()
    private val checkedPaths = mutableListOf<CheckedPath>()

    override fun activeAudit(p0: HttpRequestResponse?, p1: AuditInsertionPoint?): AuditResult {
        return auditResult(emptyList())
    }

    override fun passiveAudit(baseRequestResponse: HttpRequestResponse?): AuditResult {
        val auditIssues = mutableListOf<AuditIssue>()

        conductMetadataDiscovery(baseRequestResponse)?.let { auditIssues.add(it) }
        conductPathDiscovery(baseRequestResponse)?.let { auditIssues.add(it) }

        return auditResult( auditIssues )
    }

    override fun consolidateIssues(newIssue: AuditIssue?, existingIssue: AuditIssue?): ConsolidationAction {
        return if(existingIssue!!.baseUrl() == newIssue!!.baseUrl()) ConsolidationAction.KEEP_EXISTING
        else ConsolidationAction.KEEP_BOTH
    }

    @Suppress("MemberVisibilityCanBePrivate")
    internal fun getHostName(url: String): String {
        val uri = Utils().lenientUri(url)

        // URI.host can be null if authority has userinfo or is registry-based.
        val host = uri.host ?: uri.authority?.let { auth ->
            val noUser = auth.substringAfter('@', auth)   // drop userinfo if present
            noUser.substringBefore(':')                    // drop port if present
        }

        return host?.takeIf { it.isNotBlank() }?.lowercase() ?: "localhost"
    }

    @Suppress("MemberVisibilityCanBePrivate")
    internal fun getTargetPath(url: String): String {
        val uri = Utils().lenientUri(url)

        val scheme = uri.scheme ?: "http"

        // Prefer URI.host; if null (userinfo/registry-based), derive from authority
        val host = (uri.host ?: uri.authority?.let { auth ->
            val noUser = auth.substringAfter('@', auth) // strip userinfo if present
            noUser.substringBefore(':')                  // strip port if present
        })?.takeIf { it.isNotBlank() } ?: "localhost"

        val path = uri.rawPath?.takeIf { it.isNotEmpty() } ?: ""

        // If you want to *also* keep ?query, uncomment next line and append `query` at the end
        // val query = uri.rawQuery?.let { "?$it" } ?: ""

        return "$scheme://$host$path" // + query
    }

    private fun isWithinLastHour(dateTime: LocalDateTime): Boolean {
        val now = LocalDateTime.now()
        val oneHourAgo = now.minusHours(1)
        return dateTime.isAfter(oneHourAgo) && dateTime.isBefore(now)
    }

    private fun conductMetadataDiscovery(baseRequestResponse: HttpRequestResponse?): AuditIssue? {
        val detail = StringBuilder("")

        // This should never happen, but fall back to localhost if the hostname/IP is missing
        val hostname = getHostName(baseRequestResponse?.request()?.url() ?: "localhost")

        val index = checkedHosts.indexOfFirst { it.hostname == hostname }
        var targetHost = if (index != -1) checkedHosts[index] else null

        // Did we already scan this host in the last hour?
        if( targetHost != null && isWithinLastHour(targetHost.lastChecked)  ) {
            return null
        }

        // Conduct actual API discovery. Currently only look for API.json.
        // Future can do full OAS/Swagger detection as well in subdirs
        targetHost = APIDiscovery(api).scanHost(hostname)
        if (targetHost.apiMetadataDetected) {
            detail.append(
                "API metadata was detected at <a href=\"${targetHost.apiMetadataURL}\">${targetHost.apiMetadataURL}</a>"
            ).append("<br><br>")

            targetHost.apiMetadata?.let { metadata ->
                detail.append("Name: ${metadata.name}").append("<br>")
                detail.append("Description: ${metadata.description}").append("<br>")
                detail.append("Last Modified: ${metadata.modified}").append("<br><br>")

                detail.append("<b>Described APIs</b><br><br>")

                val urlMap = mapOf(
                    "openapi" to "OpenAPI URL",
                    "swagger" to "Swagger URL",
                    "postmancollection" to "Postman Collection URL",
                    "asyncapi" to "AsyncAPI URL",
                    "wsdl" to "WSDL URL",
                    "wadl" to "WADL URL",
                    "raml" to "RAML URL"
                )

                metadata.apis.forEach { api ->
                    detail.apply {
                        append("API Name: ${api.name}").append("<br>")
                        append("API Description: ${api.description}").append("<br>")
                        append("API Base URL: <a href=\"${api.baseURL}\">${api.baseURL}</a>").append("<br>")
                        append("API Human URL: <a href=\"${api.humanURL}\">${api.humanURL}</a>").append("<br>")
                    }

                    api.properties.forEach { prop ->
                        val propType = prop.type.lowercase()
                        urlMap[propType]?.let { description ->
                            val urlText = "$description: <a href=\"${prop.url}\">${prop.url}</a>"
                            detail.append(urlText).append("<br>")
                        }
                    }

                    detail.append("<br>")
                }
            }

            api.logging().logToOutput("Detected API configuration metadata at ${targetHost.apiMetadataURL}")
        }

        if (targetHost.apiCatalogDetected) {
            detail.append(
                "API catalog was detected at <a href=\"${targetHost.apiCatalogURL}\">${targetHost.apiCatalogURL}</a>"
            ).append("<br><br>")

            targetHost.apiCatalogData?.linkset?.forEach { link ->
                detail.append("Anchor: ${link.anchor}").append("<br>")

                link.`service-desc`?.forEach { service ->
                    detail.append("Service Description: ${service.href}, Type: ${service.type}").append("<br>")
                }

                link.`service-doc`?.forEach { service ->
                    detail.append("Service Documentation: ${service.href}, Type: ${service.type}").append("<br>")
                }

                link.`service-meta`?.forEach { service ->
                    detail.append("Service Metadata: ${service.href}, Type: ${service.type}").append("<br>")
                }

                detail.append("<br>")
            }

            api.logging().logToOutput("Detected API catalog metadata at ${targetHost.apiCatalogURL}")
        }

        checkedHosts.apply {
            if (index != -1) set(index, targetHost) else add(targetHost)
        }

        if(detail.toString() == "" ){
            return null
        }

        return AuditIssue.auditIssue(
            "API metadata discovered",
            detail.toString(),
            null,
            targetHost.apiMetadataURL,
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.CERTAIN,
            null,
            null,
            AuditIssueSeverity.LOW,
            baseRequestResponse
        )
    }

    private fun conductPathDiscovery(baseRequestResponse: HttpRequestResponse?): AuditIssue? {
        val detail = StringBuilder("")

        val target = getTargetPath(baseRequestResponse?.request()?.url() ?: "http://localhost")

        val index = checkedPaths.indexOfFirst { it.target == target }
        var targetPath = if (index != -1) checkedPaths[index] else null

        // Did we already scan this path in the last hour?
        if( targetPath != null && isWithinLastHour(targetPath.lastChecked)  ) {
            return null
        }

        runBlocking {
            targetPath = APIDocPathEnumeration(api).enumerateAPIDocPaths(target)
        }

        if(targetPath?.apiDocPathDetected == true) {
            detail.append(
                "Potential API doc path(s) have been discovered at <a href=\"$target\">$target</a>"
            ).append("<br><br>")

            targetPath!!.detectedPaths?.takeIf { it.isNotEmpty() }?.let { paths ->
                detail.append("Potential doc paths:").append("<br>")
                paths.forEach { path ->
                    detail.append(path).append("<br>")
                }
            }

            detail.append("<br>")

            api.logging().logToOutput("Detected potential API doc paths at $target")
        }

        checkedPaths.apply {
            if (index != -1) targetPath?.let { set(index, it) } else targetPath?.let { add(it) }
        }

        if(detail.toString() == "" ){
            return null
        }

        return AuditIssue.auditIssue(
            "API doc path discovered",
            detail.toString(),
            null,
            target,
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.CERTAIN,
            null,
            null,
            AuditIssueSeverity.LOW,
            baseRequestResponse
        )
    }
}