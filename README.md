# API Discovery

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=DanaEpp_APIDiscovery&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=DanaEpp_APIDiscovery)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=DanaEpp_APIDiscovery&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=DanaEpp_APIDiscovery)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=DanaEpp_APIDiscovery&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=DanaEpp_APIDiscovery)

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=DanaEpp_APIDiscovery&metric=bugs)](https://sonarcloud.io/summary/new_code?id=DanaEpp_APIDiscovery)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=DanaEpp_APIDiscovery&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=DanaEpp_APIDiscovery)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=DanaEpp_APIDiscovery&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=DanaEpp_APIDiscovery)

A Burp Suite extension that leverages [APIS.json](https://apisjson.org) and [api-catalog](https://datatracker.ietf.org/doc/draft-ietf-httpapi-api-catalog/) specifications to detect API metadata that can be used during recon. 

This extension will also do API doc path enumeration, based on previous work found in BishopFox's [Swagger Jacker](https://github.com/BishopFox/sj). Just faster, and integrated directly in Burp Suite.

This extension taps directly into Burp's [Web Vulnerability Scanner](https://portswigger.net/burp/vulnerability-scanner), and produces issues on the Dashboard and in the Site Map.