package com.danaepp.apidiscovery

import burp.api.montoya.MontoyaApi
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*


class APIDiscoveryScanCheckTest {
    private val montoya: MontoyaApi = mockk(relaxed = true)

    @Test fun `parses normal url`() {
        assertEquals("example.com", APIDiscoveryScanCheck(montoya).getHostName("https://example.com/a/b"))
    }

    @Test fun `parses funky path`() {
        val funky = "https://redacted.site/a'a%5c'b%22c%3e%3f%3e%25%7d%7d%25%25%3ec%3c[[%3f$%7b%7b%25%7d%7dcake%5c/data.json"
        assertEquals("redacted.site", APIDiscoveryScanCheck(montoya).getHostName(funky))
    }

    @Test fun `parses normal target`() {
        assertEquals("https://example.com/a/b", APIDiscoveryScanCheck(montoya).getTargetPath("https://example.com/a/b"))
    }

    @Test fun `parses funky target`() {
        val funky = "https://redacted.site/a'a%5c'b%22c%3e%3f%3e%25%7d%7d%25%25%3ec%3c[[%3f$%7b%7b%25%7d%7dcake%5c/data.json"
        val funkyEscaped = "https://redacted.site/a'a%255c'b%2522c%253e%253f%253e%2525%257d%257d%2525%2525%253ec%253c%5B%5B%253f\$%257b%257b%2525%257d%257dcake%255c/data.json"

        assertEquals(funkyEscaped, APIDiscoveryScanCheck(montoya).getTargetPath(funky))
    }
}