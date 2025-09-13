package com.danaepp.apidiscovery

import burp.api.montoya.MontoyaApi
import java.net.HttpURLConnection
import java.net.URI
import kotlinx.coroutines.*
import java.net.SocketTimeoutException
import java.io.IOException
import kotlin.math.pow
import kotlin.system.measureTimeMillis

class APIDocPathEnumeration(private val api: MontoyaApi?) {

    // Taken from BishopFox's Swagger Jacker (https://github.com/BishopFox/sj)
    private val prefixDirs = listOf(
        "",
        "/swagger",
        "/swagger/docs",
        "/swagger/latest",
        "/swagger/v1",
        "/swagger/v2",
        "/swagger/v3",
        "/swagger/static",
        "/swagger/ui",
        "/swagger-ui",
        "/swagger-docs",
        "/api-docs",
        "/api-docs/v1",
        "/api-docs/v2",
        "/apidocs",
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/v1",
        "/v2",
        "/v3",
        "/doc",
        "/docu",
        "/docs",
        "/docs/swagger",
        "/docs/swagger/v1",
        "/docs/swagger/v2",
        "/docs/swagger-ui",
        "/docs/swagger-ui/v1",
        "/docs/swagger-ui/v2",
        "/docs/v1",
        "/docs/v2",
        "/docs/v3",
        "/public",
        "/redoc"
    );

    private val docEndpoints = listOf(
        "",
        "/index",
        "/swagger",
        "/swagger-ui",
        "/swagger-resources",
        "/swagger-config",
        "/openapi",
        "/api",
        "/api-docs",
        "/apidocs",
        "/v1",
        "/v2",
        "/v3",
        "/doc",
        "/docs",
        "/apispec",
        "/apispec_1",
        "/api-merged"
    );

    private val uiEndpoints = listOf(
        "/swagger-ui-init",
        "/swagger-ui-bundle",
        "/swagger-ui-standalone-preset",
        "/swagger-ui",
        "/swagger-ui.min",
        "/swagger-ui-es-bundle-core",
        "/swagger-ui-es-bundle",
        "/swagger-ui-standalone-preset",
        "/swagger-ui-layout",
        "/swagger-ui-plugins"
    );

    private val docExtensions = listOf(
        "",
        ".json",
        ".yaml",
        ".yml",
        ".html",
        "/"
    );

    private val uiExtensions = listOf(
        "",
        ".js",
        ".html"
    );

    private val knownFileExtToIgnore = setOf(
        "ico","png","jpg","jpeg","gif","svg","webp",
        "json","xml","txt","css","js","map",
        "woff","woff2","ttf","otf",
        "pdf","csv","zip","tar","gz","webmanifest"
    )

    private fun looksLikeFile(url: String): Boolean {
        val path = try { URI(url).path ?: return false } catch (_: Exception) { return false }
        val last = path.substringAfterLast('/')
        val ext  = last.substringAfterLast('.', missingDelimiterValue = "")
        // Consider it a file if it has an extension we know, or (fallback) if it has any dot.
        return last.isNotEmpty() && (ext.lowercase() in knownFileExtToIgnore || last.contains('.'))
    }

    private fun ensureTrailingSlash(s: String) =
        if (s.endsWith("/")) s else "$s/"

    private fun parentDirUrl(url: String): String {
        val u = URI(url)
        val path = u.path ?: ""
        val dirPath = path.substringBeforeLast("/", missingDelimiterValue = "") + "/"
        return URI(u.scheme, u.authority, dirPath, u.query, u.fragment).toString()
    }

    /**
     * Smarter URL generator:
     * - If target looks like a file:
     *    - skipIfFile = true  -> return empty list
     *    - skipIfFile = false -> use the file's parent directory as base
     * - Safely handles fileExtensionList items of "", ".ext", "ext", and "/"
     */
    private fun makeURLs(
        target: String,
        endpointList: List<String>,
        fileExtensionList: List<String>,
        skipIfFile: Boolean = false
    ): List<String> {
        val baseUrl = when {
            looksLikeFile(target) && skipIfFile -> return emptyList()
            looksLikeFile(target)               -> parentDirUrl(target)
            else                                -> ensureTrailingSlash(target)
        }

        val base = URI(baseUrl)

        return prefixDirs.flatMap { dir ->
            val dirPart = dir.trim('/').let { if (it.isEmpty()) "" else "$it/" }
            val dirUri = base.resolve(dirPart)

            endpointList
                // don't produce "<base>" alone for empty dir + empty endpoint
                .filterNot { dirPart.isEmpty() && it.isEmpty() }
                .flatMap { endpoint ->
                    val ep = endpoint.trimStart('/')

                    fileExtensionList.map { ext ->
                        // Only add "." for bare words like "json".
                        // Preserve "", ".json", and "/" exactly.
                        val extPart = when {
                            ext.isEmpty() -> ""
                            ext.startsWith(".") || ext.startsWith("/") -> ext
                            else -> ".$ext"
                        }

                        dirUri.resolve(ep + extPart).toString()
                    }
                }
        }.distinct()
    }

    private fun generatePathList(target: String): List<String> {
        return buildList {
            addAll(makeURLs(target, docEndpoints, docExtensions, skipIfFile = false))
            addAll(makeURLs(target, uiEndpoints, uiExtensions, skipIfFile = false))
        }
    }

    suspend fun enumerateAPIDocPaths(target: String, dispatcher: CoroutineDispatcher = Dispatchers.IO): CheckedPath = coroutineScope {
        val urls: List<String> = generatePathList(target)

        // Run resourceExistsWithRetry in parallel for each URL
        val pathResults = urls.map { url ->
            async(dispatcher) { if (resourceExistsWithRetry(url)) url else null }
        }.awaitAll()
            .filterNotNull()
            .distinct() // Deduplicate the list

        return@coroutineScope CheckedPath(
            target = target,
            apiDocPathDetected = pathResults.isNotEmpty(),
            detectedPaths = pathResults
        )
    }

    private fun resourceExistsWithRetry(url: String, maxRetries: Int = 3, initialDelayMillis: Long = 2000L): Boolean {
        var attempt = 0

        while (attempt < maxRetries) {
            var connection: HttpURLConnection? = null
            try {
                val uri = Utils().lenientUri(url)
                connection = (uri.toURL().openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 3500
                    readTimeout = 3500
                    connect()
                }

                val responseCode = connection.responseCode
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    return true
                } else if (responseCode == HttpURLConnection.HTTP_UNAVAILABLE || responseCode == 429) {
                    println("Server returned retryable status code: $responseCode")
                } else {
                    return false
                }
            } catch (e: SocketTimeoutException) {
                println("Request timed out on attempt ${attempt + 1}")
            } catch (e: IOException) {
                println("IOException on attempt ${attempt + 1}: ${e.message}")
            } finally {
                connection?.disconnect() // Ensure connection is properly closed
            }

            // Increase delay exponentially: initialDelayMillis * 2^attempt
            val exponentialDelay = initialDelayMillis * 2.0.pow(attempt).toLong()
            attempt++

            if (attempt < maxRetries) {
                Thread.sleep(exponentialDelay)
            }
        }

        return false
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) = runBlocking {
            val target = "https://api.moovila.com/PublicAPI";

            val timeTaken = measureTimeMillis {
                val resolvedPaths: CheckedPath = APIDocPathEnumeration(null).enumerateAPIDocPaths(target)

                println("Resolved Paths:")
                for( path in resolvedPaths.detectedPaths!!) {
                    println(path)
                }
            }

            println("Completed API doc path check in $timeTaken ms.")
        }
    }
}