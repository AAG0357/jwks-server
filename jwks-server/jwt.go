package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid"`
}

type JWTClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func encodeJSON(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func SignJWT(kid string, priv *rsa.PrivateKey, claims JWTClaims) (string, error) {
	header := JWTHeader{
		Alg: "RS256",
		Typ: "JWT",
		KID: kid,
	}

	h64, err := encodeJSON(header)
	if err != nil {
		return "", err
	}
	c64, err := encodeJSON(claims)
	if err != nil {
		return "", err
	}

	message := h64 + "." + c64
	hash := sha256.Sum256([]byte(message))

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	s64 := base64.RawURLEncoding.EncodeToString(sig)
	return message + "." + s64, nil
}

func DecodeHeader(token string) (JWTHeader, error) {
	var h JWTHeader
	parts := strings.Split(token, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return h, err
	}
	err = json.Unmarshal(b, &h)
	return h, err
}

func NowUnix() int64 {
	return time.Now().Unix()
}
