# Harvest MCP Server with OAuth

An HTTP-based MCP server that provides natural language time tracking for Harvest with OAuth authentication. This server makes time tracking more intuitive by understanding natural language inputs and automatically handling common scenarios like leave requests.

## Features

- 🔐 OAuth 2.0 authentication with Harvest
- 🗣️ Natural language time entry parsing
- 🏖️ Special leave request handling (e.g., "I'm off sick today")
- ⏰ Configurable work day hours
- 🌍 Timezone support
- 🎯 Automatic project and task matching
- 📅 Smart date parsing (today, yesterday, etc.)
- 📊 Time report generation
- 🐳 Docker support
- 📝 Structured JSON logging

## Architecture

This is a single-tenant, multi-user HTTP-based MCP server where:
- Multiple users from the same Harvest company can authenticate
- Each user's OAuth tokens are stored in their session
- The server makes Harvest API calls on behalf of authenticated users
- Containerized for easy deployment in Kubernetes or other platforms

## Prerequisites

- Node.js 20+ installed (for local development)
- A Harvest account
- Harvest OAuth application credentials (see setup instructions below)

## Harvest OAuth Application Setup

1. Go to [Harvest Developer Tools](https://id.getharvest.com/developers)
2. Create a new OAuth2 application
3. Set the redirect URI to: `http://localhost:3000/auth/callback` (or your production URL)
4. Note down your Client ID and Client Secret

## Installation & Setup

### Local Development

1. Clone this repository:
```bash
git clone https://github.com/adrian-dotco/harvest-mcp-server.git
cd harvest-mcp-server
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
```

4. Edit `.env` and add your configuration:
```env
HARVEST_OAUTH_CLIENT_ID=your_client_id_here
HARVEST_OAUTH_CLIENT_SECRET=your_client_secret_here
OAUTH_REDIRECT_URI=http://localhost:3000/auth/callback
SESSION_SECRET=generate_a_random_secret_here
PORT=3000
NODE_ENV=development
STANDARD_WORK_DAY_HOURS=7.5
TIMEZONE=Australia/Perth
LOG_LEVEL=info
```

5. Build and start the server:
```bash
npm run build
npm start
```

For development with auto-reload:
```bash
npm run dev
```

### Docker Deployment

1. Build the Docker image:
```bash
npm run docker:build
```

2. Run the container:
```bash
npm run docker:run
```

Or manually:
```bash
docker build -t harvest-mcp-server .
docker run -p 3000:3000 \
  -e HARVEST_OAUTH_CLIENT_ID=your_client_id \
  -e HARVEST_OAUTH_CLIENT_SECRET=your_client_secret \
  -e OAUTH_REDIRECT_URI=https://your-domain.com/auth/callback \
  -e SESSION_SECRET=your_session_secret \
  -e PORT=3000 \
  -e STANDARD_WORK_DAY_HOURS=7.5 \
  -e TIMEZONE=Australia/Perth \
  -e LOG_LEVEL=info \
  harvest-mcp-server
```

### Kubernetes Deployment

Create a Secret for sensitive configuration:
```bash
kubectl create secret generic harvest-mcp-server \
  --from-literal=oauth-client-id=your_client_id \
  --from-literal=oauth-client-secret=your_client_secret \
  --from-literal=session-secret=your_session_secret
```

Deploy using your preferred method (Helm, kubectl, etc.) with the environment variables from the secret.

## Connecting to Claude

This server uses the HTTP transport for MCP. To connect it to Claude Desktop or Claude CLI:

### Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "harvest": {
      "url": "http://localhost:3000/mcp",
      "transport": "http"
    }
  }
}
```

### Claude CLI

Add to your `~/.claude.json` file:

```json
{
  "mcpServers": {
    "harvest": {
      "url": "http://localhost:3000/mcp",
      "transport": "http"
    }
  }
}
```

**Important Notes:**
- The MCP server must be running before starting Claude
- You must authenticate via the OAuth flow before Claude can use the tools
- Open `http://localhost:3000/auth/harvest` in a browser to authenticate
- Each user needs to authenticate individually with their Harvest account

## Usage

### Authentication

Before using the MCP tools in Claude, you need to authenticate:

1. Start the server: `npm start` (or via Docker)
2. Navigate to `http://localhost:3000/auth/harvest` in your browser
3. Log in to Harvest and authorize the application
4. You'll be redirected back with an authentication token in your session
5. Now Claude can use the MCP tools on your behalf

### Available Endpoints

#### Authentication
- `GET /auth/harvest` - Initiates OAuth flow
- `GET /auth/callback` - OAuth callback (handled automatically)
- `POST /auth/logout` - Logs out and clears session

#### Status
- `GET /` - Server info and authentication status
- `GET /health` - Health check endpoint

#### MCP Protocol
- `POST /mcp` - MCP tool calls (requires authentication)

### MCP Tools

Once authenticated, you can use these tools through the MCP protocol:

#### log_time
Log time entries using natural language. Examples:

Regular time entries:
```
"2 hours on Project X doing development work today"
"45 minutes on Project Y testing yesterday"
"3.5 hours on Project Z meetings last Friday"
```

Leave requests (automatically uses standard work day hours):
```
"I'm off sick today"
"I'm unwell today"
"Taking annual leave next week"
```

#### get_time_report
Get time reports using natural language queries. Examples:

```
"Show time report for last month"
"Get time summary for this week"
"Show hours from January 1st to January 31st"
"Show time report by client for this month"
"Get task breakdown for last week"
```

#### list_projects
List all available Harvest projects for the authenticated user.

#### list_tasks
List available tasks for a specific project.

#### list_entries
View recent time entries with optional date range filtering.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HARVEST_OAUTH_CLIENT_ID` | Yes | - | OAuth client ID from Harvest |
| `HARVEST_OAUTH_CLIENT_SECRET` | Yes | - | OAuth client secret from Harvest |
| `OAUTH_REDIRECT_URI` | Yes | - | OAuth callback URL |
| `SESSION_SECRET` | Yes | - | Secret for signing session cookies |
| `PORT` | No | 3000 | HTTP server port |
| `NODE_ENV` | No | development | Environment (development/production) |
| `STANDARD_WORK_DAY_HOURS` | No | 7.5 | Default hours for full work day |
| `TIMEZONE` | No | Australia/Perth | Timezone for date parsing |
| `LOG_LEVEL` | No | info | Logging level (debug/info/warn/error) |

### Session Configuration

- Sessions are stored in-memory by default
- Session cookies expire after 7 days
- For production with multiple instances, consider using Redis for session storage

## Development

The server is built using:
- TypeScript
- Express.js for HTTP server
- MCP SDK for protocol implementation
- Pino for structured JSON logging
- chrono-node for natural language date parsing
- Harvest API v2 with OAuth

### Project Structure

```
src/
├── server.ts           # Main Express server with OAuth and MCP endpoints
├── config.ts           # Configuration management
├── logger.ts           # Structured logging setup
├── oauth.ts            # OAuth service for Harvest authentication
├── harvest-client.ts   # Harvest API client
├── session.ts          # Session management and middleware
├── mcp-tools.ts        # MCP tool handlers
└── types/              # TypeScript type definitions
```

### Scripts

- `npm run build` - Build TypeScript to JavaScript
- `npm start` - Start the production server
- `npm run dev` - Start development server with auto-reload
- `npm run watch` - Watch TypeScript files for changes
- `npm test` - Run all tests
- `npm run test:watch` - Run tests in watch mode
- `npm run test:coverage` - Run tests with coverage report
- `npm run docker:build` - Build Docker image
- `npm run docker:run` - Run Docker container

### Testing

The project includes comprehensive unit and integration tests covering:
- Configuration management
- OAuth authentication flow
- Session middleware
- HTTP endpoints (health, auth, MCP)
- Error handling

Run tests:
```bash
npm test
```

Run tests in watch mode during development:
```bash
npm run test:watch
```

Generate coverage report:
```bash
npm run test:coverage
```

Test files are located in `src/__tests__/` and use Jest with Supertest for HTTP endpoint testing.

## Security Considerations

- Always use HTTPS in production
- Keep OAuth credentials secure and never commit them to git
- Use strong session secrets
- Configure CORS appropriately for your domain
- Session cookies are httpOnly and secure in production
- Tokens are not logged (redacted in structured logs)

## Troubleshooting

### Authentication Issues

If you're having trouble authenticating:
1. Verify your OAuth credentials are correct
2. Ensure the redirect URI matches exactly (including http/https)
3. Check server logs for detailed error messages

### Connection Issues

- Verify the server is running: `curl http://localhost:3000/health`
- Check that the port is not already in use
- Review logs for startup errors

### Docker Issues

- Ensure environment variables are properly set
- Check container logs: `docker logs <container-id>`
- Verify network connectivity for OAuth callbacks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details

## Changelog

### v0.2.0
- Converted to HTTP-based server with OAuth authentication
- Added structured JSON logging with Pino
- Implemented session management
- Added Docker support
- Multi-user support with individual authentication

### v0.1.x
- Initial STDIO-based MCP server
- Personal access token authentication
