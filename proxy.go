package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Proxy struct {
	KeyLoader KeyLoader
}

func (p *Proxy) GetTLSConfig(certPath string, keyPath string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if certPath == "" && keyPath == "" {
		return tlsConfig, nil
	}
	cert, err := p.KeyLoader.LoadKey(certPath)
	if err != nil {
		return tlsConfig, err
	}
	key, err := p.KeyLoader.LoadKey(keyPath)
	if err != nil {
		return tlsConfig, err
	}
	certificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tlsConfig, err
	}
	tlsConfig.Certificates = []tls.Certificate{certificate}
	tlsConfig.Renegotiation = tls.RenegotiateOnceAsClient
	return tlsConfig, nil
}

func (p *Proxy) ListenAndServe() error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tlsConfig, err := p.GetTLSConfig(r.Header.Get(CertHeader), r.Header.Get(KeyHeader))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		urlString := r.Header.Get(UrlHeader)
		if urlString == "" {
			http.Error(w, "Url not provided", http.StatusBadRequest)
			return
		}
		requestUrl, err := url.Parse(urlString)
		if err != nil {
			http.Error(w, "Bad url", http.StatusBadRequest)
			return
		}
		method := r.Header.Get(MethodHeader)
		if method == "" {
			http.Error(w, "Method not provided", http.StatusBadRequest)
			return
		}
		followRedirectsHeader := r.Header.Get(FollowRedirectsHeader)
		followRedirects, err := strconv.ParseBool(followRedirectsHeader)
		if err != nil {
			followRedirects = true
		}
		outReqHeaders := map[string][]string{}
		canonicalPrefix := http.CanonicalHeaderKey(RequestHeaderPrefix)
		for key, value := range r.Header {
			canonicalKey := http.CanonicalHeaderKey(key)
			if strings.HasPrefix(canonicalKey, canonicalPrefix) {
				outReqHeaders[strings.TrimPrefix(canonicalKey, canonicalPrefix)] = value
			}
		}
		outReq := &http.Request{
			Method: method,
			URL:    requestUrl,
			Header: outReqHeaders,
			Body:   r.Body,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if followRedirects {
					return nil
				}
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(outReq)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				fmt.Println(err)
			}
		}(resp.Body)
		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			fmt.Println("Error:", err)
		}
	})

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		algorithmString := r.Header.Get(SignAlgorithmHeader)
		if algorithmString == "" {
			http.Error(w, "No "+SignAlgorithmHeader+" header specified", http.StatusBadRequest)
			return
		}
		keyName := r.Header.Get(KeyHeader)
		if keyName == "" {
			http.Error(w, "No "+KeyHeader+" header specified", http.StatusBadRequest)
			return
		}
		keyContent, err := p.KeyLoader.LoadKey(keyName)
		if err != nil {
			http.Error(w, "Error loading key", http.StatusBadRequest)
			return
		}
		privateKey, err := loadPrivateKey(keyContent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		algorithmMap := map[string]int{
			"rs256": rs256,
			"ps256": ps256,
		}
		algorithm, ok := algorithmMap[algorithmString]
		if !ok {
			http.Error(w, "Unsupported algorithm", http.StatusBadRequest)
			return
		}
		signature, err := sign(privateKey, body, algorithm)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, err = w.Write([]byte(signature))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return http.ListenAndServe(":"+port, nil)
}
