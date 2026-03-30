\# JWKS Server (Go)



Runs a RESTful JWKS server on port 8080.



\## Endpoints



\### GET /jwks

Returns public keys in JWKS format. Only unexpired keys are served.



\### POST /auth

Returns a signed JWT (no body required). JWT header includes `kid`.



\### POST /auth?expired=true

Returns a JWT signed with the expired key and an expired `exp`.



\## Run

```powershell

go run .

Project 2 – JWKS Server with SQLite

Features:
- SQLite database for key storage
- RSA key generation
- JWT signing
- JWKS endpoint
- Expired key handling
- SQL injection protection via parameterized queries

Endpoints:
POST /auth
GET /.well-known/jwks.json

Note:
Test client was not provided, functionality verified using curl and unit tests.


