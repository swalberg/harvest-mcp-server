# Harvest MCP Server Specification

## Overview

This project starts out as an MCP server for the Harvest V2 API (https://help.getharvest.com/api-v2/) using the STDIO protocol and requiring the user to individually set up IDs and keys that are manually created on the Harvest site.

The goal is to convert this to a hosted server where users log in and authenticate to the Harvest API via OAuth (https://help.getharvest.com/api-v2/authentication-api/authentication/authentication/#oauth2-authorization-flow)

Further, the application should log with JSON and run in a container using a dockerfile.

## Architecture

**Single-tenant, multi-user HTTP-based MCP server** where:
- One Harvest account/company with multiple users
- OAuth credentials (client ID/secret) from environment variables
- HTTP transport for MCP protocol (SSE is deprecated)
- Users authenticate via OAuth, tokens stored in cookies
- Server acts as a proxy, making Harvest API calls on behalf of authenticated users
- Containerized with structured JSON logging
- Kubernetes-ready (but no k8s manifests needed in repo)

## Implementation Requirements

### 1. OAuth Flow
- OAuth authorization endpoint (`/auth/harvest`)
- OAuth callback endpoint (`/auth/callback`)
- Token exchange and cookie storage
- Middleware to validate authentication on MCP requests
- Automatic token refresh when tokens expire
- User identification by Harvest user ID from OAuth token

### 2. HTTP Server
- Replace STDIO transport with HTTP transport
- Use Express framework
- Implement MCP over HTTP endpoints using official `@modelcontextprotocol/server-http`
- Session/cookie management
- In-memory session storage (MVP - can be upgraded to Redis later)

### 3. Structured Logging
- Add pino logging library for performance
- JSON-formatted logs with appropriate levels
- Request correlation IDs
- Consistent log format across all operations

### 4. Containerization
- Create Dockerfile with multi-stage build
- Non-root user for security
- Health check endpoint (`/health`)
- Optimized for small image size

### 5. Configuration

Environment variables:
- `HARVEST_OAUTH_CLIENT_ID` - OAuth client ID (registered with Harvest)
- `HARVEST_OAUTH_CLIENT_SECRET` - OAuth client secret
- `OAUTH_REDIRECT_URI` - OAuth callback URL
- `SESSION_SECRET` - Secret for signing session cookies
- `PORT` - HTTP server port (default: 3000)
- `STANDARD_WORK_DAY_HOURS` - Default hours for full work day (default: 7.5)
- `TIMEZONE` - Default timezone (default: Australia/Perth)
- `LOG_LEVEL` - Logging level (default: info)

### 6. Dependencies to Add
- Web framework: Express
- Session management: express-session, cookie-parser
- Logging: pino, pino-http
- OAuth: axios (already present) for token exchange
- MCP HTTP: @modelcontextprotocol/server-http

## Multi-User Support

Since this is single-tenant (one Harvest company) but multi-user:
- Multiple users from the same company authenticate with their individual Harvest accounts
- Each user's OAuth tokens are stored in their session cookies
- Server makes Harvest API calls using the authenticated user's tokens
- Each user sees their own projects, tasks, and time entries based on their Harvest permissions

## Security Considerations

- HTTPS required in production (handled upstream by Kubernetes)
- Secure cookie flags (httpOnly, secure, sameSite)
- Input validation on all endpoints
- Rate limiting on OAuth endpoints
- CORS policy configuration
- No token storage in logs
- Session timeout/expiration

## Endpoints

### Authentication
- `GET /auth/harvest` - Initiates OAuth flow, redirects to Harvest
- `GET /auth/callback` - OAuth callback, exchanges code for tokens
- `POST /auth/logout` - Clears session

### Health & Status
- `GET /health` - Health check endpoint for container orchestration
- `GET /` - Server info/status

### MCP Protocol
- MCP endpoints handled by `@modelcontextprotocol/server-http`
- Authentication middleware validates session before processing MCP requests

## Development Workflow

1. Follow TDD with unit and integration tests
2. Use TypeScript with strict mode
3. Use npm scripts for common operations (test, build, run, lint, dev)
4. Maintain project documentation
5. Update README with new setup instructions