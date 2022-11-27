package main

import "os"

var projectId = os.Getenv("projectId")

const CertHeader = "X-Proxy-Cert"
const KeyHeader = "X-Proxy-Key"
const FollowRedirectsHeader = "X-Proxy-Follow-Redirects"
const UrlHeader = "X-Proxy-Url"
const MethodHeader = "X-Proxy-Method"
const SignAlgorithmHeader = "X-Proxy-Signature-Algorithm"
const RequestHeaderPrefix = "X-Request-"
