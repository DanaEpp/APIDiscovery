package com.danaepp.apidiscovery

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

@Serializable
data class LinkSet(
    val linkset: List<Link>
)

@Serializable
data class Link(
    val anchor: String,
    val `service-desc`: List<Service>? = null,
    val status: List<Service>? = null,
    val `service-doc`: List<Service>? = null,
    val `service-meta`: List<Service>? = null
)

@Serializable
data class Service(
    val href: String,
    val type: String
)

class APICatalogParser(private val api: MontoyaApi) {
    fun parse(metadata: String) : LinkSet? {
        var apiCatalogData: LinkSet? = null

        try {
            val json = Json { ignoreUnknownKeys = true; }
            apiCatalogData = json.decodeFromString<LinkSet>(metadata)
        }
        catch(ex: SerializationException) {
            api.logging().logToError("Serialization exception:" + ex.message)
        }
        catch (exc: Exception) {
            api.logging().logToError("General Exception: " + exc.message)
        }

        return apiCatalogData
    }
}