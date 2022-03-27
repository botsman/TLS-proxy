package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
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
	return tlsConfig, nil
}

func (p *Proxy) ListenAndServe() error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme == "" {
			// This handler is expected to handle proxy requests.
			// It should not be used for the regular request.
			// Perhaps there is a better way to handle this.
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		transport := http.Transport{}
		tlsConfig, err := p.GetTLSConfig(r.Header.Get(CertHeader), r.Header.Get(KeyHeader))
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		r.Header.Del(CertHeader)
		r.Header.Del(KeyHeader)
		outReq := &http.Request{
			Method: r.Method,
			URL:    r.URL,
			Header: r.Header,
			Body:   r.Body,
		}

		if tlsConfig != nil {
			transport.TLSClientConfig = tlsConfig
		}
		followRedirectsHeader := r.Header.Get(FollowRedirectsHeader)
		r.Header.Del(FollowRedirectsHeader)
		followRedirects, err := strconv.ParseBool(followRedirectsHeader)
		if err != nil {
			followRedirects = true
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
		keyContent, err := p.KeyLoader.LoadKey(r.Header.Get(KeyHeader))
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
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
		signature, err := sign(privateKey, body)
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
