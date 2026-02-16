package main

import (
"encoding/json"
"net/http"
"net/http/httptest"
"testing"
"time"
)

func TestJWKSOnlyReturnsActiveKey(t *testing.T) {
s, _ := NewServer()

req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
rr := httptest.NewRecorder()
s.routes().ServeHTTP(rr, req)

if rr.Code != http.StatusOK {
t.Fatal("expected 200")
}

var jwks JWKS
if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
t.Fatal(err)
}

if len(jwks.Keys) != 1 {
t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
}

if jwks.Keys[0].KID != s.Active.KID {
t.Fatal("expected active key kid")
}
}

func TestJWKSMethodNotAllowed(t *testing.T) {
s, _ := NewServer()

req := httptest.NewRequest(http.MethodPost, "/jwks", nil)
rr := httptest.NewRecorder()
s.routes().ServeHTTP(rr, req)

if rr.Code != http.StatusMethodNotAllowed {
t.Fatal("expected 405")
}
}

func TestAuthReturnsJWTWithActiveKID(t *testing.T) {
s, _ := NewServer()

req := httptest.NewRequest(http.MethodPost, "/auth", nil)
rr := httptest.NewRecorder()
s.routes().ServeHTTP(rr, req)

if rr.Code != http.StatusOK {
t.Fatal("expected 200")
}

var resp map[string]string
_ = json.Unmarshal(rr.Body.Bytes(), &resp)

token := resp["token"]
if token == "" {
t.Fatal("expected token")
}

h, err := DecodeHeader(token)
if err != nil {
t.Fatal(err)
}

if h.KID != s.Active.KID {
t.Fatal("expected active key kid")
}
}

func TestAuthExpiredUsesExpiredKID(t *testing.T) {
s, _ := NewServer()

req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
rr := httptest.NewRecorder()
s.routes().ServeHTTP(rr, req)

if rr.Code != http.StatusOK {
t.Fatal("expected 200")
}

var resp map[string]string
_ = json.Unmarshal(rr.Body.Bytes(), &resp)

token := resp["token"]
h, err := DecodeHeader(token)
if err != nil {
t.Fatal(err)
}

if h.KID != s.Expired.KID {
t.Fatal("expected expired key kid")
}
}

func TestAuthMethodNotAllowed(t *testing.T) {
s, _ := NewServer()

req := httptest.NewRequest(http.MethodGet, "/auth", nil)
rr := httptest.NewRecorder()
s.routes().ServeHTTP(rr, req)

if rr.Code != http.StatusMethodNotAllowed {
t.Fatal("expected 405")
}
}

func TestGenerateRSAKeyPairHasKIDAndKey(t *testing.T) {
kp, err := GenerateRSAKeyPair(time.Now().Add(1 * time.Minute))
if err != nil {
t.Fatal(err)
}

if kp.KID == "" {
t.Fatal("expected non-empty kid")
}

if kp.Priv == nil {
t.Fatal("expected private key")
}
}

func TestBuildJWKSFiltersExpired(t *testing.T) {
active, _ := GenerateRSAKeyPair(time.Now().Add(1 * time.Minute))
expired, _ := GenerateRSAKeyPair(time.Now().Add(-1 * time.Minute))

j := BuildJWKS(time.Now(), []*KeyPair{active, expired})

if len(j.Keys) != 1 {
t.Fatalf("expected 1 key, got %d", len(j.Keys))
}

if j.Keys[0].KID != active.KID {
t.Fatal("expected active key")
}
}

func TestSignJWTAndDecodeHeader(t *testing.T) {
kp, _ := GenerateRSAKeyPair(time.Now().Add(1 * time.Minute))

claims := JWTClaims{
Sub: "mock-user",
Iat: time.Now().Unix(),
Exp: time.Now().Add(1 * time.Minute).Unix(),
}

token, err := SignJWT(kp.KID, kp.Priv, claims)
if err != nil {
t.Fatal(err)
}

h, err := DecodeHeader(token)
if err != nil {
t.Fatal(err)
}

if h.KID != kp.KID {
t.Fatal("kid mismatch")
}

if h.Alg != "RS256" {
t.Fatal("expected RS256")
}
}
