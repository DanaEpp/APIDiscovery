package com.danaepp.apidiscovery

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

@Serializable
data class ApiJson(
    val name: String,
    val description: String,
    val url: String,
    val created: String,
    val modified: String,
    val specificationVersion: String,
    val apis: List<Api> = emptyList(),
    val common: List<Common> = emptyList()
)

@Serializable
data class Api(
    val name: String,
    val description: String,
    val humanURL: String,
    val baseURL: String,
    val properties: List<Property> = emptyList()
)

@Serializable
data class Common(
    val name: String = "",
    val type: String,
    val mediaType: String = "",
    val url: String
)

@Serializable
data class Property(
    val type: String,
    val url: String
)

class APIMetadataParser(private val api: MontoyaApi) {
    fun parse(metadata: String) : ApiJson? {
        var apiMetadata: ApiJson? = null

        try {
            val json = Json { ignoreUnknownKeys = true; }
            apiMetadata = json.decodeFromString<ApiJson>(metadata)
        }
        catch(ex: SerializationException) {
            api.logging().logToError("Serialization exception in metadata parser:" +
                    ex.message + "\n" + ex.stackTraceToString())
        }
        catch (exc: Exception) {
            api.logging().logToError("General Exception in metadata parser: " + exc.message)
        }

        return apiMetadata
    }
}