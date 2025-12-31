# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TrustyAuth Proxy is an authn-focused HTTP reverse proxy written in Go that provides authentication and CSRF protection middleware. It sits in front of an origin server and validates requests before proxying them through.

## Build and Development Commands

```bash
# Build the binary (outputs to dist/ta-proxy)
make

# Run tests
make test

# Run a specific test
go test ./middleware -run TestAuth

# Clean build artifacts
make clean

# Run the proxy server
./dist/ta-proxy -config etc/trustyauth.yml
```

## Architecture

### Middleware Chain Pattern

The proxy uses the standard Go middleware pattern `func(http.Handler) http.Handler` implemented in `proxy.go:NewReverseProxy()`. Middleware is registered sequentially, with each wrapping the previous handler:

```go
var handler http.Handler = rp
handler = middleware.Auth(handler, key, logger)
handler = middleware.CSRF(handler, key, logger)
handler = middleware.Logging(handler, logger)
```

Execution order (outermost to innermost):
1. **Logging** (outermost) - Request/response logging with timing
2. **CSRF** - CSRF token validation for state-changing methods
3. **Auth** (innermost) - Authentication via encrypted cookie
4. **ReverseProxy** - Final handler that proxies to origin

Each middleware function returns an `http.Handler` that wraps the next handler and calls `next.ServeHTTP(w, r)` to continue the chain. This pattern makes it easy to add, remove, or reorder middleware.

### Security Components

**Authentication (`middleware/auth.go`)**
- Validates `ta` cookie containing encrypted user email
- Uses AES-GCM encryption from `crypto/aes.go`
- Sets `X-TA-USER-EMAIL` header for downstream use
- Returns 403 on missing/invalid cookie or malformed email

**CSRF Protection (`middleware/csrf.go`)**
- Protects POST, PUT, PATCH, DELETE requests
- Validates `X-CSRF-TOKEN` header matches `XSRF-TOKEN` cookie
- Uses `golang.org/x/net/xsrftoken` for token generation/validation
- Generates new token for each response
- XSRF-TOKEN cookie is HttpOnly and set to SameSite=Lax

**JWT Authentication Handler (`handlers/auth.go`)**
- Handles `/auth` endpoint for JWT-based authentication
- NOT protected by Auth or CSRF middleware (creates the auth cookie)
- Validates JWT tokens with HS256 signature verification
- Validates standard claims (exp, iat, nbf, sub) and custom `htu` claim
- Validates `htu` hostname matches configured domain
- Prevents XSS via redirect URL scheme validation (only http/https allowed)
- Encrypts user email and sets secure session cookie
- Redirects to intended destination from `htu` claim

**Encryption (`crypto/aes.go`)**
- AES-256-GCM encryption for authentication cookies
- Requires minimum 32-byte keys (enforced at startup in `main.go:46`)
- Truncates keys longer than 32 bytes to exactly 32 bytes
- Base64 URL-safe encoding for cookie values

**JWT Validation (`internal/jwt`)**
- `Claims`: Custom claims structure with `htu` (HTTP Target URI) and standard JWT claims
- `Validator`: Validates JWT signatures, time-based claims, hostname matching, and email format
- Validates `htu` hostname exactly matches configured domain
- Reuses email validation logic for `sub` claim

### Configuration

The server reads YAML configuration via `-config` flag:

```yaml
addr: :80                        # Bind address
origin: http://localhost:5678    # Origin server URL
key: <32+ byte encryption key>   # Shared key for crypto and CSRF
ta_secret: <JWT signing secret>  # Shared secret for JWT signature verification
domain: example.com              # Allowed domain for JWT hostname validation
```

Configuration fields:
- **`key`**: Used for AES-GCM encryption/decryption of auth cookies and CSRF token generation/validation
- **`ta_secret`**: Shared secret for JWT signature verification (HS256) on the `/auth` endpoint
- **`domain`**: Allowed domain for hostname validation in JWT `htu` claim

### Request Flow

**JWT Authentication Flow (via `/auth` endpoint)**:
1. External auth app generates JWT with `sub` (email) and `htu` (redirect URL) claims
2. External auth app redirects user to `/auth?token=<jwt>`
3. Auth handler validates JWT signature using `ta_secret`
4. Auth handler validates `htu` hostname matches configured `domain`
5. Auth handler validates `sub` contains valid email address
6. Auth handler validates redirect URL scheme (http/https only)
7. Auth handler encrypts email and sets `ta` cookie
8. Auth handler redirects user to `htu` URL (HTTP 302)

**Proxied Request Flow (all routes except `/auth`)**:
1. Request arrives at `/` (catch-all route with middleware)
2. Logging middleware captures start time
3. CSRF middleware validates token for state-changing methods
4. Auth middleware decrypts `ta` cookie and validates email
5. Auth middleware sets `X-TA-USER-EMAIL` header
6. ReverseProxy modifies request (Host, URL.Host, URL.Scheme) and proxies to origin
7. Response status and body copied back to client
8. Logging middleware records request details including user email

### Testing Notes

All packages have corresponding `_test.go` files. Tests use table-driven test patterns with subtests. When adding middleware features, update both the middleware and its tests.

### Key Security Constraints

- Encryption key must be at least 32 bytes (validated at startup and in crypto package)
- CSRF tokens are required for POST/PUT/PATCH/DELETE
- Auth cookies must contain valid email addresses
- XSRF-TOKEN cookies are HttpOnly to prevent XSS attacks
