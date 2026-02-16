package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"time"
)

type KeyPair struct {
	KID    string
	Expiry time.Time
	Priv   *rsa.PrivateKey
}

func newKID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func GenerateRSAKeyPair(expiry time.Time) (*KeyPair, error) {
	kid, err := newKID()
	if err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		KID:    kid,
		Expiry: expiry,
		Priv:   priv,
	}, nil
}
