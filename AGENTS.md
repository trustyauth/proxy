# Repository Guidelines

## Project Overview

TrustyAuth Proxy is an authentication-focused HTTP reverse proxy written in Go. It sits in front of an origin server, validates requests via encrypted cookies and CSRF tokens, and proxies authenticated traffic through. The `/auth` endpoint handles JWT-based login and sets the session cookie.

## Project Structure & Module Organization

- `cmd/ta-proxy/` - CLI entry point, configuration loading, and server startup
- `proxy.go` - Core reverse proxy implementation at repo root
- `internal/` - Supporting packages:
  - `internal/cookie/` - Cookie name constants and utilities
  - `internal/crypto/` - AES-GCM encryption for cookies
  - `internal/email/` - Email validation
  - `internal/handlers/` - HTTP handlers (e.g., `/auth` endpoint)
  - `internal/jwt/` - JWT claims and validation
  - `internal/middleware/` - Middleware functions (auth, CSRF, logging)
- `tools/` - Helper binaries for generating test cookies/JWTs (build into `dist/`)
- `etc/` - Docker Compose files and sample configurations

Unit tests accompany the code as `*_test.go` files (e.g., `proxy_test.go`, `internal/middleware/auth_test.go`). Keep test fixtures next to the tests that consume them.

## Build, Test, and Development Commands

```bash
# Build the binary (outputs to dist/ta-proxy)
make

# Run all tests
make test

# Run a specific test
go test ./internal/middleware -run TestAuth

# Format all Go sources
make fmt

# Clean build artifacts
make clean

# Build helper binaries (generate-cookie, generate-jwt)
make bins

# Generate test cookie/JWT for manual testing
make cookie
make jwt

# Run the proxy server locally
./dist/ta-proxy -config etc/trustyauth.yml
```

## Coding Style & Naming Conventions

- Follow idiomatic Go: use tabs for indentation, run `go fmt` (`make fmt`) before committing
- Use lowercase package names (`internal/email`) and PascalCase for exported types/functions
- Config structs should include YAML tags mirroring existing patterns (`yaml:"tls"`)
- Keep handlers small and pure; inject dependencies instead of reaching across packages
- Run `go vet` when making changes to catch common issues

## Architecture

### Middleware Chain Pattern

The proxy uses the standard Go middleware pattern `func(http.Handler) http.Handler`. Middleware is registered by wrapping handlers sequentially in `proxy.go:NewReverseProxy()`:

```go
var handler http.Handler = rp
handler = middleware.Auth(handler, config.Key, logger)
handler = middleware.CSRF(handler, config.Key, logger)
handler = middleware.Logging(handler, logger)
mux.Handle("/", handler)
```

**Execution order** (outermost to innermost):
1. **Logging** (outermost) - Request/response logging with timing
2. **CSRF** - Token validation for state-changing methods
3. **Auth** (innermost) - Cookie validation, sets `X-TA-USER-EMAIL` header
4. **ReverseProxy** - Final handler that proxies to origin

The last middleware registered is the first to execute. Each middleware calls `next.ServeHTTP(w, r)` to continue the chain.

### Creating New Middleware

Middleware functions live in `internal/middleware/`. Follow this pattern:

```go
package middleware

import (
    "log/slog"
    "net/http"
)

// MyMiddleware returns a middleware handler that does X.
func MyMiddleware(next http.Handler, dep SomeDependency, logger slog.Logger) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Pre-processing (runs before downstream handlers)
        // e.g., validate request, set headers, check auth

        // Reject the request if needed:
        // w.WriteHeader(http.StatusForbidden)
        // return

        // Continue to the next handler
        next.ServeHTTP(w, r)

        // Post-processing (runs after downstream handlers)
        // e.g., log response, modify headers
    })
}
```

Always create a corresponding `*_test.go` file with table-driven tests.

### Registering Middleware on a Handler

To add middleware to a route, wrap the handler in `proxy.go:NewReverseProxy()`:

```go
// For protected routes (with full middleware chain)
var handler http.Handler = rp
handler = middleware.Auth(handler, config.Key, logger)
handler = middleware.CSRF(handler, config.Key, logger)
handler = middleware.Logging(handler, logger)
mux.Handle("/", handler)

// For unprotected routes (e.g., /auth only needs logging)
var authHandler http.Handler = handlers.NewAuthHandler(...)
authHandler = middleware.Logging(authHandler, logger)
mux.Handle("GET /auth", authHandler)
```

### Security Components

**Authentication (`internal/middleware/auth.go`)**
- Validates `ta` cookie containing AES-GCM encrypted user email
- Sets `X-TA-USER-EMAIL` header for downstream services
- Returns 403 on missing/invalid cookie or malformed email

**CSRF Protection (`internal/middleware/csrf.go`)**
- Protects POST, PUT, PATCH, DELETE requests
- Validates `X-CSRF-TOKEN` header matches `XSRF-TOKEN` cookie
- Uses `golang.org/x/net/xsrftoken` for token generation/validation
- XSRF-TOKEN cookie is HttpOnly, SameSite=Lax

**JWT Authentication Handler (`internal/handlers/auth.go`)**
- Handles `/auth` endpoint (not protected by Auth/CSRF middleware)
- Validates JWT with HS256 signature using `ta_secret`
- Validates claims: `exp`, `iat`, `nbf`, `sub` (email), `htu` (redirect URL)
- Validates `htu` hostname matches configured `domain`
- Encrypts email into `ta` cookie and redirects to `htu`

**Encryption (`internal/crypto/aes.go`)**
- AES-256-GCM encryption for authentication cookies
- Requires minimum 32-byte keys (enforced at startup)
- Base64 URL-safe encoding for cookie values

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
6. ReverseProxy forwards request to origin (modifies Host, URL)
7. Response copied back to client
8. Logging middleware records request details

## Configuration

### Basic Configuration

```yaml
addr: :80                              # Bind address
origin: http://localhost:5678          # Origin server URL
key: <32+ byte encryption key>         # For cookie encryption and CSRF tokens
ta_secret: <JWT signing secret>        # For JWT signature verification (HS256)
domain: example.com                    # Allowed domain for JWT htu claim validation
```

### TLS Mode: off (default)

Plain HTTP mode. Use when TLS termination is handled externally (e.g., by a load balancer).

```yaml
addr: :8888
origin: http://localhost:5678
key: your-32-byte-encryption-key-here!
ta_secret: your-jwt-signing-secret-key
domain: example.com
tls:
  mode: "off"
```

### TLS Mode: manual

Provide your own certificate and key files. Optionally configure HTTP-to-HTTPS redirect.

```yaml
addr: :443
origin: http://localhost:5678
key: your-32-byte-encryption-key-here!
ta_secret: your-jwt-signing-secret-key
domain: example.com
tls:
  mode: "manual"
  manual:
    cert: "/etc/ssl/cert.pem"
    key: "/etc/ssl/key.pem"
  http_redirect: ":80"    # Optional: redirect HTTP to HTTPS
```

### TLS Mode: acme (not yet implemented)

Automatic certificate provisioning via Let's Encrypt. Configuration structure:

```yaml
tls:
  mode: "acme"
  acme:
    domains: ["example.com", "www.example.com"]
    cache_dir: "/var/cache/ta-proxy/certs"
    email: "admin@example.com"    # Optional contact email
  http_redirect: ":80"
```

## Docker Testing

### Testing Off Mode (HTTP)

Start the stack with plain HTTP on port 8888:

```bash
# Start the stack
make up

# View proxy logs
make devlogs

# Generate a test cookie and make a request
make cookie
# Copy the cookie value from output, then:
curl -H "Cookie: ta=<cookie-value>" http://localhost:8888/

# Stop the stack
make down
```

### Testing Manual TLS Mode

Start the stack with TLS on port 443 (requires `mkcert` installed):

```bash
# Generate self-signed certificates (one-time setup)
# Requires: brew install mkcert && mkcert -install
make certs

# Start the stack with TLS
make up-tls

# View proxy logs
make devlogs

# Generate a TLS-compatible test cookie and make a request
make cookie-tls
# Copy the cookie value from output, then:
curl -k -H "Cookie: ta=<cookie-value>" https://localhost/

# Test HTTP redirect
curl -I http://localhost/

# Stop the stack
make down
```

Note: Use `-k` flag with curl to skip certificate verification for self-signed certs.

## Testing Guidelines

- Name tests `TestThingDoesX` and place them in the same package as the code
- Use table-driven tests with descriptive `name` fields to aid `go test -run`
- Cover happy path, edge cases, and auth/TLS failure modes
- `proxy_test.go` is the reference for request/response assertions
- Run `make test` locally before every PR

## Commit & Pull Request Guidelines

- Commits follow short, imperative messages (`Add cookie package`, `Fix CSRF token expiry`)
- Keep messages under ~60 characters
- Each PR should describe the change, include reproduction/verification steps, and link related issues
- Attach logs or `curl` samples when touching networking or TLS
- Run `make fmt && make test` before requesting review

## Security Notes

- Encryption key must be at least 32 bytes (validated at startup)
- CSRF tokens are required for POST/PUT/PATCH/DELETE requests
- Auth cookies must contain valid email addresses
- Never commit secrets (`key`, `ta_secret`, TLS cert paths) - use local files or environment variables
- When testing TLS locally, use non-privileged ports (e.g., `:8080`) unless running with elevated permissions
