# API Discovery

A Burp Suite extension that leverages [APIS.json](https://apisjson.org) and [api-catalog](https://datatracker.ietf.org/doc/draft-ietf-httpapi-api-catalog/) specifications to detect API metadata that can be used during recon. 

This extension will also do API doc path enumeration, based on previous work found in BishopFox's [Swagger Jacker](https://github.com/BishopFox/sj). Just faster, and integrated directly in Burp Suite.

This extension taps directly into Burp's [Web Vulnerability Scanner](https://portswigger.net/burp/vulnerability-scanner), and produces issues on the Dashboard and in the Site Map.