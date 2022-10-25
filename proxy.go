package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

type Proxy struct {
	KeyLoader KeyLoader
}

func (p *Proxy) GetTLSConfig(certPath string, keyPath string) (*tls.Config, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	tlsConfig := &tls.Config{}
	cert, err := p.KeyLoader.LoadKey(certPath)
	if err != nil {
		return nil, err
	}
	key, err := p.KeyLoader.LoadKey(keyPath)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = []tls.Certificate{certificate}
	tlsConfig.InsecureSkipVerify = true
	return tlsConfig, nil
}

func (p *Proxy) ListenAndServe() error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		transport := http.Transport{}
		tlsConfig, err := p.GetTLSConfig(r.Header.Get(CertHeader), r.Header.Get(KeyHeader))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Header.Del(CertHeader)
		r.Header.Del(KeyHeader)
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
		r.Header.Del(UrlHeader)
		method := r.Header.Get(MethodHeader)
		if method == "" {
			http.Error(w, "Method not provided", http.StatusBadRequest)
			return
		}
		r.Header.Del(MethodHeader)
		followRedirectsHeader := r.Header.Get(FollowRedirectsHeader)
		r.Header.Del(FollowRedirectsHeader)
		followRedirects, err := strconv.ParseBool(followRedirectsHeader)
		if err != nil {
			followRedirects = true
		}
		outReq := &http.Request{
			Method: method,
			URL:    requestUrl,
			Header: r.Header,
			Body:   r.Body,
		}

		if tlsConfig != nil {
			transport.TLSClientConfig = tlsConfig
		}
		client := &http.Client{
			Transport: &transport,
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
			http.Error(w, "Algorithm not provided", http.StatusBadRequest)
			return
		}
		r.Header.Del(SignAlgorithmHeader)
		keyContent, err := p.KeyLoader.LoadKey(r.Header.Get(KeyHeader))
		if err != nil {
			http.Error(w, "Error loading key", http.StatusBadRequest)
			return
		}
		privateKey, err := loadPrivateKey(keyContent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Header.Del(KeyHeader)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		algorithm := map[string]int{
			"rs256": rs256,
			"ps256": ps256,
		}[algorithmString]
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
