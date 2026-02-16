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



