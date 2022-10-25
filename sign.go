package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	rs256 = iota
	ps256
)

func loadPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("failed to parse PEM private key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return privateKey, nil
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return privateKey.(*rsa.PrivateKey), nil
	default:
		fmt.Println("Unsupported key type:", block.Type)
		return nil, errors.New("failed to parse PEM private key")
	}
}

func sign(privateKey *rsa.PrivateKey, data []byte, algorithm int) (string, error) {
	hash := sha256.New()
	hash.Write(data)
	hashed := hash.Sum(nil)
	var signature []byte
	var err error
	switch algorithm {
	case rs256:
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	case ps256:
		signature, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed, nil)
	default:
		return "", errors.New("unsupported algorithm")
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}
