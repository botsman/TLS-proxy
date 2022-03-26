# TLS and eIDAS proxy server

Simple proxy server meant to be run in secure Google Cloud environment.

Server support two use-cases:
1. TLS connection to any server using TLS certificates from Google Cloud Secret Manager

TLS connection is implemented using regular proxy server.
You need to specify name of a public certificate and a private key in the following headers:
`X-Cert`
`X-Key`
Those headers are removed from actual request
You can also specify `X-Follow-Redirects` header to follow redirects


2. Signing data with eIDAS private key
In order to do that just send a request to `/sign` endpoint with your data in the body and `X-Key` header

Proxy is meant to be run in the secured environment, that is why no authentication is implemented.

This project is just an experiment and the way for me to learn Go. Some (all?) of the things might be done in a better way.