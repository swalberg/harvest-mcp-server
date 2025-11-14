# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

This is a Harvest MCP (Model Context Protocol) Server that acts as an OAuth bridge between MCP clients (like Claude CLI) and the Harvest time tracking API. It implements a complete OAuth 2.0 authorization server that wraps Harvest's OAuth authentication.

## Architecture

### OAuth Flow Layers

1. **MCP Client Layer**: Claude CLI or other MCP clients
2. **OAuth Provider Layer**: This server acts as an OAuth authorization server
   - Endpoints: `/oauth/authorize`, `/oauth/token`, `/oauth/register`
   - Discovery: `/.well-known/oauth-authorization-server`
3. **Harvest OAuth Client Layer**: Server authenticates with Harvest on behalf of users
   - Uses Harvest OAuth credentials from environment
4. **Harvest API Layer**: Server makes API calls to Harvest using user tokens

### Key Components

- **JWT Service** (`src/jwt-service.ts`): Stateless JWT token generation and verification with encrypted Harvest credentials
- **Auth Code Store** (`src/token-store.ts`): Redis-backed store (with in-memory fallback) for temporary OAuth authorization codes (5 min TTL)
- **Redis Client** (`src/redis-client.ts`): Redis client factory and connection management (optional - for persistence)
- **OAuth Service** (`src/oauth.ts`): Handles Harvest OAuth flow (token exchange, refresh)
- **MCP Tools** (`src/mcp-tools.ts`): Implements MCP tool handlers for Harvest operations
- **Express App** (`src/app.ts`): All HTTP endpoints and middleware
- **Session Management** (`src/session.ts`): Session types and auth middleware (for browser flows)

## Testing Requirements

**CRITICAL**: Always write comprehensive tests for new features and endpoints.

### Test Guidelines

1. **New Endpoints**: Every new endpoint must have corresponding tests
2. **Happy Path**: Test successful flows
3. **Error Cases**: Test all error conditions (400, 401, 500)
4. **Edge Cases**: Test missing parameters, invalid data, expired tokens
5. **Integration**: Test complete OAuth flows end-to-end

### Test Structure

- **Unit Tests**: `src/__tests__/*.test.ts`
- **Test Framework**: Jest with Supertest for HTTP testing
- **Mocking**: Use nock for external API mocking (Harvest API calls)
- **Session Testing**: Use `request.agent()` for session persistence

### Running Tests

```bash
npm test                  # Run all tests
npm run test:watch        # Watch mode
npm run test:coverage     # Coverage report
```

**Current Test Count**: 132 tests across 8 test suites (including JWT and auth code tests)

## OAuth Provider Implementation

### Endpoints

1. **Discovery**: `GET /.well-known/oauth-authorization-server`
   - Returns OAuth server metadata per RFC 8414

2. **Registration**: `POST /oauth/register`
   - Dynamic client registration per RFC 7591
   - Accepts: `redirect_uris`, `client_name`
   - Returns: `client_id`, `client_secret`

3. **Authorization**: `GET /oauth/authorize`
   - Redirects to Harvest OAuth with state
   - Stores MCP client params in session
   - Returns authorization code to MCP client after Harvest auth

4. **Token Exchange**: `POST /oauth/token`
   - Exchanges authorization code for JWT Bearer token
   - Validates redirect_uri, code expiration
   - Returns JWT access_token (stateless) valid for 7 days
   - JWT contains encrypted Harvest credentials

5. **MCP Endpoint**: `POST /mcp`
   - Accepts Bearer token OR session authentication
   - Routes to MCP tool handlers

## Configuration

### Environment Variables

Required:
- `HARVEST_OAUTH_CLIENT_ID`: Harvest OAuth app client ID
- `HARVEST_OAUTH_CLIENT_SECRET`: Harvest OAuth app secret
- `OAUTH_REDIRECT_URI`: Harvest OAuth callback URL (e.g., `http://localhost:3000/auth/callback`)
- `SESSION_SECRET`: Secret for session encryption

Optional:
- `SERVER_BASE_URL`: Base URL for OAuth provider (default: `http://localhost:{PORT}`)
- `PORT`: Server port (default: 3000)
- `NODE_ENV`: Environment (development/production)
- `STANDARD_WORK_DAY_HOURS`: Default work hours (default: 7.5)
- `TIMEZONE`: Timezone for time operations (default: Australia/Perth)
- `LOG_LEVEL`: Logging level (default: info)

Redis (optional - for persistence of sessions and temporary auth codes):
- `REDIS_URL`: Complete Redis connection URL (e.g., `redis://user:password@host:port`)
  - OR use individual parameters:
- `REDIS_HOST`: Redis server hostname
- `REDIS_PORT`: Redis server port (default: 6379)
- `REDIS_PASSWORD`: Redis password (if required)
- `REDIS_TLS`: Enable TLS for Redis connection (true/false)

**Note**: If Redis is not configured, the server falls back to in-memory storage. Access tokens are now JWTs (stateless) so Redis is only needed for:
1. Session persistence (browser flows)
2. Temporary authorization codes (5 min TTL)
3. Multi-instance deployments

## Development Practices

### Code Changes

1. **Read First**: Always read relevant files before editing
2. **Test Coverage**: Write tests for new features before committing
3. **Type Safety**: Maintain TypeScript strict mode compliance
4. **Error Handling**: Return proper HTTP status codes with descriptive errors
5. **Logging**: Use structured logging with pino

### Adding New Endpoints

When adding new endpoints:
1. Implement the endpoint in `src/app.ts`
2. Update session types if needed (`src/session.ts`)
3. Add corresponding tests in `src/__tests__/`
4. Test both success and error cases
5. Ensure all tests pass: `npm test`
6. Build to check TypeScript: `npm run build`

### OAuth Error Responses

Follow RFC 6749 error format:
```json
{
  "error": "error_code",
  "error_description": "Human readable description"
}
```

Common error codes:
- `invalid_request`: Missing/invalid parameters
- `invalid_grant`: Invalid/expired authorization code
- `unsupported_grant_type`: Unsupported grant_type
- `invalid_redirect_uri`: Mismatched redirect_uri

## MCP Tools

The server exposes these Harvest operations as MCP tools:
- `log_time`: Log time entries using natural language
- `list_projects`: List available Harvest projects
- `list_tasks`: List tasks for a project
- `list_entries`: List recent time entries
- `get_time_report`: Get time reports using natural language

## Authentication Modes

The server supports two authentication modes:

1. **Session-based** (Browser): Uses express-session with cookies
   - Session stored in Redis or in-memory
   - Harvest credentials stored in session
   - Used for browser-based interactions

2. **JWT Bearer token** (MCP clients): Uses stateless JWT tokens
   - JWT contains encrypted Harvest credentials (AES-256-GCM)
   - Signed with SESSION_SECRET for integrity
   - No server-side storage required (stateless)
   - Valid for 7 days
   - Self-contained authentication

Both modes provide access to the same Harvest API operations.

## Multi-User Architecture

- **Single-tenant**: One Harvest account/company
- **Multi-user**: Multiple users from same company
- **Access Tokens**: JWT (stateless, no storage needed)
- **Auth Codes**: Redis or in-memory (temporary, 5 min TTL)
- **Sessions**: Redis or in-memory (browser flows)

### Storage Modes

1. **Development/Single-Instance**: Without Redis configuration, uses in-memory storage.
   - Auth codes stored in memory (5 min TTL)
   - Sessions stored in memory
   - Access tokens are JWTs (no storage needed)
   - Lost on restart, but JWTs remain valid until expiration

2. **Production/Multi-Instance**: With Redis configured via environment variables:
   - Persistent sessions across server restarts
   - Shared session state for multiple server instances
   - Shared auth codes for OAuth flow
   - JWTs remain stateless (no Redis needed for access tokens)
   - Automatic TTL-based expiration for sessions and auth codes

### Redis Configuration

Configure Redis using either:
- Single `REDIS_URL` environment variable, or
- Individual `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_TLS` variables

See Configuration section above for details.

## Security Considerations

1. **CSRF Protection**: State parameter in OAuth flow
2. **Token Expiration**: Authorization codes expire in 5 minutes, JWTs expire in 7 days
3. **Secure Cookies**: HttpOnly, Secure flags in production
4. **Token Redaction**: Sensitive fields redacted in logs
5. **One-time Codes**: Authorization codes are single-use
6. **JWT Encryption**: Harvest credentials encrypted with AES-256-GCM in JWT payload
7. **JWT Signing**: JWTs signed with SESSION_SECRET to prevent tampering
8. **Stateless Security**: No server-side token storage means no centralized attack surface for access tokens

## Common Tasks

### Update OAuth Provider

If modifying OAuth provider endpoints:
1. Update endpoint in `src/app.ts`
2. Update discovery metadata if needed
3. Add/update tests in `src/__tests__/oauth-provider.test.ts`
4. Test complete OAuth flow end-to-end

### Add New MCP Tool

1. Add tool handler in `src/mcp-tools.ts`
2. Register in `setupHandlers()`
3. Add Harvest API method in `src/harvest-client.ts` if needed
4. Add tests in `src/__tests__/server.test.ts`

### Modify Session Data

1. Update types in `src/session.ts` (SessionData interface)
2. Update session middleware if needed
3. Update tests that use sessions

## Troubleshooting

### OAuth Errors
- Check `SERVER_BASE_URL` matches actual deployment URL
- Verify Harvest OAuth credentials are correct
- Check redirect_uri matches registered URL in Harvest app

### Session Issues
- Ensure cookies are enabled
- Check CORS configuration for cross-origin requests
- Verify SESSION_SECRET is set

### Token Issues
- JWTs expire after 7 days (cannot be revoked, must wait for expiration)
- Harvest tokens inside JWTs expire after 18 hours (need to re-authenticate)
- Invalid JWT signature means SESSION_SECRET has changed or token was tampered with
- Authorization codes expire after 5 minutes (must restart OAuth flow)

## Related Documentation

- [Harvest OAuth API](https://help.getharvest.com/api-v2/authentication-api/authentication/authentication/)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [Dynamic Client Registration RFC 7591](https://tools.ietf.org/html/rfc7591)
- [OAuth Discovery RFC 8414](https://tools.ietf.org/html/rfc8414)
- [Model Context Protocol](https://modelcontextprotocol.io/)
