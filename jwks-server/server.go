package main

import (
	"encoding/json"
	"net/http"
	"time"
)

type Server struct {
	Active  *KeyPair
	Expired *KeyPair
}

func NewServer() (*Server, error) {
	now := time.Now()

	active, err := GenerateRSAKeyPair(now.Add(30 * time.Minute))
	if err != nil {
		return nil, err
	}

	expired, err := GenerateRSAKeyPair(now.Add(-30 * time.Minute))
	if err != nil {
		return nil, err
	}

	return &Server{
		Active:  active,
		Expired: expired,
	}, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	jwks := BuildJWKS(time.Now(), []*KeyPair{s.Active, s.Expired})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	_, expiredMode := r.URL.Query()["expired"]

	var kp *KeyPair
	if expiredMode {
		kp = s.Expired
	} else {
		kp = s.Active
	}

	now := time.Now()

	exp := now.Add(5 * time.Minute).Unix()
	if expiredMode {
		exp = kp.Expiry.Unix()
	}

	claims := JWTClaims{
		Sub: "mock-user",
		Iat: now.Unix(),
		Exp: exp,
	}

	token, err := SignJWT(kp.KID, kp.Priv, claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}
