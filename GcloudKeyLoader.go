package main

import (
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"context"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"log"
)

type GcloudKeyLoader struct {
}

func (g GcloudKeyLoader) LoadKey(key string) ([]byte, error) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return []byte{}, err
	}
	defer func(client *secretmanager.Client) {
		err := client.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(client)
	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: key,
	}
	result, err := client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		return []byte{}, err
	}
	return result.Payload.Data, nil
}
