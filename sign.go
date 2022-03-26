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
	"io/ioutil"
)

func readKey(path string) ([]byte, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyContent, err := readKey(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyContent)
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

func sign(privateKey *rsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.New()
	hash.Write(data)
	hashed := hash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return encodedSignature, nil
}
