package main

type KeyLoader interface {
	LoadKey(key string) ([]byte, error)
}
