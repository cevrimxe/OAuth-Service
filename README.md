# OAuth-Service

A Go-based OAuth authentication service that supports Google and Apple Sign-In providers. This service does not provide traditional username/password registration - authentication is exclusively through OAuth providers.

## Features

- **Google OAuth 2.0** - Authenticate users with their Google accounts
- **Apple Sign In** - Authenticate users with their Apple IDs
- **JWT Token Generation** - Issue JWT tokens for authenticated sessions
- **PostgreSQL Database** - Store user data and OAuth tokens securely

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 14 or higher

## Configuration

The service is configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://postgres:postgres@localhost:5432/oauth_service?sslmode=disable` |
| `JWT_SECRET` | Secret key for JWT signing | `your-secret-key` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `GOOGLE_REDIRECT_URL` | Google OAuth redirect URL | `http://localhost:8080/auth/google/callback` |
| `APPLE_CLIENT_ID` | Apple Sign In client ID (Service ID) | - |
| `APPLE_TEAM_ID` | Apple Developer Team ID | - |
| `APPLE_KEY_ID` | Apple Sign In Key ID | - |
| `APPLE_PRIVATE_KEY` | Apple Sign In private key (PEM format) | - |
| `APPLE_REDIRECT_URL` | Apple Sign In redirect URL | `http://localhost:8080/auth/apple/callback` |

## Installation

```bash
# Clone the repository
git clone https://github.com/cevrimxe/OAuth-Service.git
cd OAuth-Service

# Install dependencies
go mod download

# Build the service
go build -o oauth-service ./cmd/server
```

## Database Setup

Create a PostgreSQL database:

```sql
CREATE DATABASE oauth_service;
```

The service will automatically run migrations on startup.

## Running the Service

```bash
# Set required environment variables
export DATABASE_URL="postgres://user:password@localhost:5432/oauth_service?sslmode=disable"
export JWT_SECRET="your-secure-secret-key"
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
# ... set other required variables

# Run the service
./oauth-service
```

## API Endpoints

### Health Check
```
GET /health
```

### Google OAuth

**Initiate Login:**
```
GET /auth/google
```
Redirects to Google OAuth consent screen.

**OAuth Callback:**
```
GET /auth/google/callback
```
Handles Google OAuth callback and returns JWT token.

### Apple Sign In

**Initiate Login:**
```
GET /auth/apple
```
Redirects to Apple Sign In page.

**OAuth Callback:**
```
POST /auth/apple/callback
```
Handles Apple Sign In callback (form POST) and returns JWT token.

### Protected Routes

**Get Current User:**
```
GET /api/user
Authorization: Bearer <jwt-token>
```

## Response Format

All endpoints return JSON responses in the following format:

```json
{
  "success": true,
  "data": { ... }
}
```

Or for errors:

```json
{
  "success": false,
  "error": "error message"
}
```

## Authentication Response

Successful authentication returns:

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "name": "User Name",
      "provider": "google",
      "provider_id": "123456789",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  }
}
```

## Setting Up OAuth Providers

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to Credentials → Create Credentials → OAuth client ID
5. Configure the OAuth consent screen
6. Add authorized redirect URIs

### Apple Sign In

1. Go to [Apple Developer Portal](https://developer.apple.com/)
2. Create an App ID with Sign In with Apple capability
3. Create a Services ID for web authentication
4. Create a Sign In with Apple key
5. Configure return URLs

## Testing

```bash
go test ./... -v
```

## License

MIT License