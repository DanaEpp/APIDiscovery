package com.danaepp.apidiscovery

import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*

class UtilsTest {

    @Test fun `parses normal host`() {
        val uri = Utils().lenientUri("https://example.com/a/b")
        assertEquals("example.com", uri.host)
    }

    @Test fun `parses normal url`() {
        val cleanUri = "https://example.com/a/b"
        val uri = Utils().lenientUri(cleanUri)
        assertEquals(cleanUri, uri.toURL().toString())
    }

    @Test fun `parses funky url`() {
        val funky        = "https://redacted.site/a'a%5c'b%22c%3e%3f%3e%25%7d%7d%25%25%3ec%3c[[%3f$%7b%7b%25%7d%7dcake%5c/data.json"
        val funkyEscaped = "https://redacted.site/a'a%255c'b%2522c%253e%253f%253e%2525%257d%257d%2525%2525%253ec%253c%5B%5B%253f\$%257b%257b%2525%257d%257dcake%255c/data.json"
        val uri = Utils().lenientUri(funky)
        assertEquals(funkyEscaped, uri.toURL().toString())
    }


}