package com.danaepp.apidiscovery

import burp.api.montoya.MontoyaApi
import java.net.HttpURLConnection
import java.net.URI

class APIDiscovery(private val api: MontoyaApi) {
    fun scanHost(host: String ): CheckedHost {
        val (metadataDetected, metadataUrl) = apiMetadataExists(host)
        var metadata: ApiJson? = null

        // TODO: Support parsing APIS.yaml in the future
        if (metadataDetected && metadataUrl.endsWith(".json")) {
            getResource(metadataUrl)?.let { rawMetadata ->
                metadata = APIMetadataParser(api).parse(rawMetadata)
            }
        }

        var catalogData: LinkSet? = null
        val (catalogDetected, catalogUrl) = apiCatalogExists(host)
        if( catalogDetected ) {
            getResource(catalogUrl)?.let { cdata ->
                catalogData = APICatalogParser(api).parse(cdata)
            }
        }

        return CheckedHost(
            hostname = host,
            apiMetadataDetected = metadataDetected,
            apiMetadataURL = metadataUrl,
            apiMetadata = metadata,
            apiCatalogDetected = catalogDetected,
            apiCatalogURL = catalogUrl,
            apiCatalogData = catalogData
        )
    }

    // Sample: https://developer.apis.io/apis.json
    private fun apiMetadataExists(host: String): Pair<Boolean, String> {
        val paths = listOf("apis.json", "apis.yaml")
        return checkIfExists( host, paths )
    }

    private fun apiCatalogExists(host: String): Pair<Boolean, String> {
        val paths = listOf(".well-known/api-catalog")
        return checkIfExists( host, paths )
    }

    private fun checkIfExists( host: String, paths: List<String> ) : Pair<Boolean, String> {
        val protocols = listOf("https", "http")

        for (protocol in protocols) {
            for (path in paths) {
                val targetUrl = "$protocol://$host/$path"
                if (resourceExist(targetUrl)) {
                    return Pair(true, targetUrl)
                }
            }
        }

        return Pair(false, "")
    }

    private fun resourceExist(url: String): Boolean {
        return try {
            val connection = URI(url).toURL().openConnection() as HttpURLConnection
            connection.requestMethod = "HEAD"
            connection.connect()
            val responseCode = connection.responseCode
            connection.disconnect()
            responseCode == HttpURLConnection.HTTP_OK
        } catch (e: Exception) {
            false
        }
    }

    private fun getResource(url: String): String? {
        var content: String? = null
        val connection = URI(url).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 5000
            connection.readTimeout = 5000

            val responseCode = connection.responseCode
            if (responseCode == HttpURLConnection.HTTP_OK) {
                content = connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                api.logging().logToError("HTTP error code: $responseCode")
            }
        } catch (e: Exception) {
            api.logging().logToError("getResource() failed: ${e.message}")
        } finally {
            connection.disconnect()
        }
        return content
    }
}