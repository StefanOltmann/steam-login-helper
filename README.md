# Steam Login Helper

![Kotlin](https://img.shields.io/badge/kotlin-2.3.0-blue.svg?logo=kotlin)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![JVM](https://img.shields.io/badge/-JVM-gray.svg?style=flat)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-gray?&logo=GitHub-Sponsors&logoColor=EA4AAA)](https://github.com/sponsors/StefanOltmann)

Enables users to authenticate via Steam and generates a JWT token as proof of Steam ID ownership.

## How it works

1. Client calls `/login` to start Steam OpenID flow.
2. Steam redirects back to `/callback/...` with OpenID parameters.
3. The service verifies the OpenID response with Steam and extracts the Steam ID.
4. A JWT is created and signed (ES256) and returned:
    - If a `redirect` is provided to `/login`, the user is redirected to `redirect?token=...`.
    - Otherwise, an HTML page shows the token.

## Endpoints

- `GET /` - Health/status with uptime and version.
- `GET /login` - Start OpenID login (requires API key if configured).
- `GET /callback/` - OpenID callback (requires API key if configured).
- `GET /callback/{redirectUrlBase64}` - Same as above, with redirect target.
- `GET /generate-keys` - Generates an ES256 keypair and prints to logs (requires API key if configured and `ALLOW_KEY_GENERATION=true`).

## Configuration (environment variables)

These are read via `System.getenv(...)` at startup. Missing required values will fail the service.

| Variable               | Required | Default | Description                                                       |
|------------------------|----------|---------|-------------------------------------------------------------------|
| `ISSUER`               | yes      | -       | JWT issuer claim.                                                 |
| `JWT_PRIVATE_KEY`      | yes      | -       | Base64-encoded EC P-256 private key in DER format.                |
| `SALT`                 | yes      | -       | Salt added to Steam ID before hashing.                            |
| `API_KEY`              | no       | -       | If set, requests must include `x-api-key` header with this value. |
| `ALLOW_KEY_GENERATION` | no       | `false` | Enables `/generate-keys` endpoint when `true`.                    |

### JWT key format

The service uses ES256 and expects `JWT_PRIVATE_KEY` to be a Base64 string of a DER-encoded EC P-256 private key. You can generate a keypair via the `/generate-keys` endpoint if enabled, then copy the logged values.

## Docker usage

### Pull or build

```bash
docker build -t steam-login-helper:local .
```

### Run

```bash
docker run --rm -p 8080:8080 ^
  -e ISSUER="steam-login-helper" ^
  -e JWT_PRIVATE_KEY="BASE64_DER_PRIVATE_KEY" ^
  -e SALT="your-salt" ^
  -e API_KEY="optional-api-key" ^
  steam-login-helper:local
```

### Docker Compose example

```yaml
services:
    steam-login-helper:
        image: steam-login-helper:local
        ports:
            - "8080:8080"
        environment:
            ISSUER: "steam-login-helper"
            JWT_PRIVATE_KEY: "BASE64_DER_PRIVATE_KEY"
            SALT: "your-salt"
            API_KEY: "optional-api-key"
            ALLOW_KEY_GENERATION: "false"
```

## Example requests

Start login (with API key):

```bash
curl -H "x-api-key: optional-api-key" "http://localhost:8080/login"
```

Start login with redirect:

```bash
curl -H "x-api-key: optional-api-key" "http://localhost:8080/login?redirect=https://your-app.example/callback"
```

Generate keys (if enabled):

```bash
curl -H "x-api-key: optional-api-key" "http://localhost:8080/generate-keys"
```

## Docker multi-arch build (amd64 + arm64)

Docker buildx is required for native multi-arch images:

```bash
docker buildx create --use --name oni-seed-browser-builder
docker buildx inspect --bootstrap
docker buildx build --platform linux/amd64,linux/arm64 -t your-registry/oni-seed-browser-backend:latest --push .
```

Notes:

- Multi-arch builds must be pushed to a registry; `--load` only loads a single arch image locally.
- If you only want one architecture locally, use `--platform linux/arm64` (or `linux/amd64`) with `--load`.
