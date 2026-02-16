package main

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func PublicJWKFromRSA(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		KID: kid,
		N:   base64url(pub.N.Bytes()),
		E:   base64url(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func BuildJWKS(now time.Time, keys []*KeyPair) JWKS {
	var jwks JWKS
	for _, k := range keys {
		if k.Expiry.After(now) {
			jwks.Keys = append(jwks.Keys, PublicJWKFromRSA(&k.Priv.PublicKey, k.KID))
		}
	}
	return jwks
}
