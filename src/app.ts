/**
 * Express app factory for testability
 */
import express, { Request, Response, NextFunction, Express } from 'express';
import session from 'express-session';
import RedisStore from 'connect-redis';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { createRequire } from 'module';
import { randomBytes } from 'crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { Config } from './config.js';
import { Logger } from './logger.js';
import { OAuthService } from './oauth.js';
import { HarvestClient } from './harvest-client.js';
import { requireAuth, getHarvestTokens } from './session.js';
import { McpToolHandlers } from './mcp-tools.js';
import { TokenStore } from './token-store.js';
import { OAuthStateManager } from './oauth-state.js';
import { createRedisClient } from './redis-client.js';

const require = createRequire(import.meta.url);
const pinoHttp = require('pino-http');

interface McpSession {
  server: Server;
  transport: SSEServerTransport;
  harvestClient: HarvestClient;
}

export function createApp(config: Config, logger: Logger): Express {
  const app = express();

  // Create Redis client if configured
  const redisClient = createRedisClient(config, logger);

  // Services
  const oauthService = new OAuthService(config, logger);
  const mcpToolHandlers = new McpToolHandlers(config, logger);
  const tokenStore = new TokenStore(logger, redisClient);
  const oauthStateManager = new OAuthStateManager(config.sessionSecret);

  // Track active MCP sessions
  const mcpSessions = new Map<string, McpSession>();

  // Middleware
  app.use(cors({
    origin: config.nodeEnv === 'production' ? false : true,
    credentials: true,
  }));

  // Skip JSON parsing for /mcp/message - the MCP SDK needs to read the raw body
  app.use((req, res, next) => {
    if (req.path === '/mcp/message') {
      return next();
    }
    express.json()(req, res, next);
  });

  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  // Session configuration
  const sessionConfig: session.SessionOptions = {
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: config.nodeEnv === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
    // Force session to be saved back to the session store on every request
    rolling: true,
  };

  // Use Redis for session storage if available
  if (redisClient) {
    logger.info('Using Redis for session storage');
    sessionConfig.store = new RedisStore({
      client: redisClient,
      prefix: 'harvest:session:',
    });
  } else {
    logger.info('Using in-memory session storage');
  }

  app.use(session(sessionConfig));

  // HTTP request logging
  app.use(
    pinoHttp({
      logger,
      autoLogging: {
        ignore: (req: any) => req.url === '/health',
      },
    })
  );

  // Request correlation ID
  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = randomBytes(16).toString('hex');
    res.setHeader('X-Request-ID', requestId);
    next();
  });

  // Health check endpoint
  app.get('/health', (req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '0.2.0',
    });
  });

  // OAuth Discovery Endpoints
  app.get('/.well-known/oauth-authorization-server', (req: Request, res: Response) => {
    res.json({
      issuer: config.serverBaseUrl,
      authorization_endpoint: `${config.serverBaseUrl}/oauth/authorize`,
      token_endpoint: `${config.serverBaseUrl}/oauth/token`,
      registration_endpoint: `${config.serverBaseUrl}/oauth/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['plain', 'S256'],
    });
  });

  // Root endpoint
  app.get('/', (req: Request, res: Response) => {
    const isAuthenticated = !!(req.session.harvestTokens && req.session.harvestAccountId);

    res.json({
      name: 'Harvest MCP Server',
      version: '0.2.0',
      authenticated: isAuthenticated,
      user: isAuthenticated ? { id: req.session.harvestUserId } : undefined,
      endpoints: {
        auth: '/auth/harvest',
        logout: '/auth/logout',
        mcp: '/mcp',
        health: '/health',
      },
    });
  });

  // OAuth: Initiate authentication
  app.get('/auth/harvest', (req: Request, res: Response) => {
    try {
      const state = randomBytes(32).toString('hex');
      req.session.oauthState = state;

      const authUrl = oauthService.getAuthorizationUrl(state);

      logger.info({
        state,
        sessionID: req.sessionID,
        hasSession: !!req.session,
      }, 'Initiating OAuth flow');

      // Save session before redirecting to ensure state is persisted
      req.session.save((err) => {
        if (err) {
          logger.error({ error: err, sessionID: req.sessionID }, 'Failed to save session');
          return res.status(500).json({
            error: 'Session error',
            message: 'Failed to initialize authentication',
          });
        }
        logger.info({
          sessionID: req.sessionID,
          state,
          redirectUrl: authUrl,
        }, 'Session saved, redirecting to Harvest');
        res.redirect(authUrl);
      });
    } catch (error) {
      logger.error({ error }, 'Error initiating OAuth flow');
      res.status(500).json({
        error: 'OAuth initialization failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // OAuth: Callback
  app.get('/auth/callback', async (req: Request, res: Response) => {
    try {
      const { code, state, error } = req.query;

      // Log detailed session information for debugging
      logger.info({
        hasSession: !!req.session,
        sessionID: req.sessionID,
        hasCode: !!code,
        hasState: !!state,
      }, 'OAuth callback received');

      if (error) {
        logger.error({ error }, 'OAuth authorization error');
        return res.status(400).json({
          error: 'OAuth authorization failed',
          message: error as string,
        });
      }

      if (!state || typeof state !== 'string') {
        logger.error({ hasState: !!state }, 'Missing state parameter');
        return res.status(400).json({
          error: 'Invalid state parameter',
          message: 'Missing state parameter',
        });
      }

      // Try stateless state verification first (for MCP OAuth provider flow)
      let stateData = oauthStateManager.verifyState(state);

      if (stateData) {
        // Stateless OAuth provider flow
        logger.info({
          hasClientId: !!stateData.clientId,
          hasRedirectUri: !!stateData.redirectUri,
        }, 'Stateless state token verified successfully');
      } else if (state === req.session.oauthState) {
        // Session-based browser flow
        logger.info({ sessionID: req.sessionID }, 'Session-based state verified successfully');
        delete req.session.oauthState;
        // Create empty state data for browser flow (no MCP client info)
        stateData = {
          nonce: state,
          timestamp: Date.now(),
        };
      } else {
        // Neither stateless nor session-based state is valid
        logger.error({
          hasSession: !!req.session,
          sessionID: req.sessionID,
          hasSessionState: !!req.session.oauthState,
          stateLength: state.length,
        }, 'Invalid OAuth state - neither stateless nor session-based validation succeeded');
        return res.status(400).json({
          error: 'Invalid state parameter',
          message: 'Invalid or expired state token. Please try again.',
        });
      }

      if (!code || typeof code !== 'string') {
        return res.status(400).json({
          error: 'Missing authorization code',
        });
      }

      const tokenData = await oauthService.exchangeCodeForToken(code);

      req.session.harvestTokens = {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        expires_in: tokenData.expires_in,
        token_type: tokenData.token_type,
      };
      req.session.harvestAccountId = tokenData.account_id;
      req.session.tokenExpiresAt = Date.now() + tokenData.expires_in * 1000;

      const harvestClient = new HarvestClient(tokenData.access_token, tokenData.account_id, logger);
      const user = await harvestClient.getCurrentUser();
      req.session.harvestUserId = user.id;

      logger.info(
        {
          userId: user.id,
          accountId: tokenData.account_id,
        },
        'User authenticated successfully'
      );

      // Check if this is part of OAuth provider flow (stateless state has clientId/redirectUri)
      if (stateData.clientId && stateData.redirectUri) {
        // Generate and store authorization code for MCP client
        const authCode = await tokenStore.storeAuthCode(
          req.session.harvestTokens!,
          req.session.harvestAccountId!,
          user.id,
          stateData.redirectUri
        );

        // Build redirect URL with code and state
        const redirectUrl = new URL(stateData.redirectUri);
        redirectUrl.searchParams.set('code', authCode);
        if (stateData.clientState) {
          redirectUrl.searchParams.set('state', stateData.clientState);
        }

        logger.info({
          userId: user.id,
          clientId: stateData.clientId,
          codePrefix: authCode.substring(0, 8),
        }, 'Redirecting to MCP client with authorization code');
        return res.redirect(redirectUrl.toString());
      }

      // Standard browser OAuth flow
      res.json({
        success: true,
        message: 'Authentication successful',
        user: {
          id: user.id,
          email: user.email,
          name: `${user.first_name} ${user.last_name}`,
        },
      });
    } catch (error) {
      logger.error({ error }, 'Error in OAuth callback');
      res.status(500).json({
        error: 'Authentication failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // Logout
  app.post('/auth/logout', (req: Request, res: Response) => {
    const userId = req.session.harvestUserId;

    req.session.destroy((err) => {
      if (err) {
        logger.error({ error: err, userId }, 'Error destroying session');
        return res.status(500).json({
          error: 'Logout failed',
        });
      }

      logger.info({ userId }, 'User logged out successfully');

      res.json({
        success: true,
        message: 'Logged out successfully',
      });
    });
  });

  // OAuth Provider Endpoints (for MCP clients)
  // Authorization endpoint - redirects to Harvest OAuth
  app.get('/oauth/authorize', (req: Request, res: Response) => {
    try {
      const { client_id, redirect_uri, state, response_type } = req.query;

      if (response_type !== 'code') {
        return res.status(400).json({
          error: 'unsupported_response_type',
          error_description: 'Only response_type=code is supported',
        });
      }

      // Create stateless signed state token with OAuth parameters embedded
      const harvestState = oauthStateManager.createState({
        clientId: client_id as string,
        redirectUri: redirect_uri as string,
        clientState: state as string,
      });

      // Redirect to Harvest OAuth
      const authUrl = oauthService.getAuthorizationUrl(harvestState);
      logger.info({
        stateLength: harvestState.length,
        clientId: client_id,
      }, 'OAuth authorization initiated for MCP client (stateless)');

      res.redirect(authUrl);
    } catch (error) {
      logger.error({ error }, 'Error in OAuth authorization');
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to initiate authorization',
      });
    }
  });

  // Token endpoint - exchanges code for access token
  app.post('/oauth/token', express.urlencoded({ extended: true }), async (req: Request, res: Response) => {
    try {
      const { grant_type, code, redirect_uri } = req.body;

      if (grant_type !== 'authorization_code') {
        return res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: 'Only grant_type=authorization_code is supported',
        });
      }

      if (!code) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing code parameter',
        });
      }

      if (!redirect_uri) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing redirect_uri parameter',
        });
      }

      // Consume the authorization code (one-time use, with redirect URI verification)
      const authData = await tokenStore.consumeAuthCode(code, redirect_uri);
      if (!authData) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid or expired authorization code',
        });
      }

      // Generate access token
      const accessToken = await tokenStore.storeToken(
        authData.harvestTokens,
        authData.harvestAccountId,
        authData.harvestUserId
      );

      logger.info({ userId: authData.harvestUserId }, 'Access token issued for MCP client');

      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 7 * 24 * 60 * 60, // 7 days
      });
    } catch (error) {
      logger.error({ error }, 'Error in OAuth token exchange');
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to exchange authorization code',
      });
    }
  });

  // Dynamic client registration endpoint
  app.post('/oauth/register', express.json(), async (req: Request, res: Response) => {
    try {
      const { redirect_uris, client_name } = req.body;

      // Validate redirect_uris
      if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        return res.status(400).json({
          error: 'invalid_redirect_uri',
          error_description: 'redirect_uris must be a non-empty array',
        });
      }

      // Generate client credentials (simplified - no persistence needed for single-user server)
      const clientId = randomBytes(16).toString('hex');
      const clientSecret = randomBytes(32).toString('hex');

      logger.info({ clientId, clientName: client_name }, 'OAuth client registered');

      // Return client credentials per RFC 7591
      res.status(201).json({
        client_id: clientId,
        client_secret: clientSecret,
        client_name: client_name || 'MCP Client',
        redirect_uris: redirect_uris,
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_post',
      });
    } catch (error) {
      logger.error({ error }, 'Error in client registration');
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to register client',
      });
    }
  });

  // MCP protocol endpoints using SSE transport
  // GET /mcp - Establish SSE connection
  app.get('/mcp', async (req: Request, res: Response) => {
    try {
      let harvestTokens;
      let harvestAccountId;
      let userId;

      // Check for Bearer token authentication (for MCP clients)
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const accessToken = authHeader.substring(7);
        const tokenData = await tokenStore.getToken(accessToken);

        if (!tokenData) {
          return res.status(401).json({
            error: 'Invalid or expired access token',
            message: 'Please re-authenticate',
          });
        }

        harvestTokens = tokenData.harvestTokens;
        harvestAccountId = tokenData.harvestAccountId;
        userId = tokenData.harvestUserId;
        logger.debug({ userId }, 'Bearer token authentication successful');
      } else {
        // Fall back to session-based authentication (for browser)
        const credentials = getHarvestTokens(req.session);
        if (!credentials) {
          return res.status(401).json({
            error: 'Not authenticated',
            message: 'Please authenticate with Harvest first',
            authUrl: '/auth/harvest',
          });
        }

        harvestTokens = credentials.tokens;
        harvestAccountId = credentials.accountId;
        userId = req.session.harvestUserId;
        logger.debug({ userId }, 'Session authentication successful');
      }

      // Create Harvest client for this session
      const harvestClient = new HarvestClient(
        harvestTokens.access_token,
        harvestAccountId,
        logger
      );

      // Create SSE transport
      const transport = new SSEServerTransport('/mcp/message', res);

      // Create new MCP server instance for this session
      const mcpServer = new Server(
        {
          name: 'harvest-server',
          version: '0.2.0',
        },
        {
          capabilities: {
            tools: {},
          },
        }
      );

      // Setup tool handlers for this server
      let currentClient: HarvestClient | null = harvestClient;
      mcpToolHandlers.setupHandlers(mcpServer, () => currentClient);

      // Store session
      mcpSessions.set(transport.sessionId, {
        server: mcpServer,
        transport,
        harvestClient,
      });

      logger.info({
        userId,
        sessionId: transport.sessionId,
        totalActiveSessions: mcpSessions.size,
      }, 'MCP SSE connection established');

      // Handle connection close
      mcpServer.onclose = () => {
        logger.info({ sessionId: transport.sessionId }, 'MCP session closed');
        mcpSessions.delete(transport.sessionId);
      };

      // Connect the server to the transport
      await mcpServer.connect(transport);
    } catch (error) {
      logger.error({ error }, 'Error establishing MCP SSE connection');
      res.status(500).json({
        error: 'Failed to establish MCP connection',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // POST /mcp/message - Handle MCP messages via POST
  // NOTE: This endpoint does NOT use express.json() middleware because the MCP SDK's
  // handlePostMessage needs to read the raw request body stream using getRawBody().
  // Body parsing is explicitly skipped for this endpoint in the middleware setup above.
  app.post('/mcp/message', async (req: Request, res: Response) => {
    try {
      const sessionId = req.query.sessionId as string;

      if (!sessionId) {
        logger.warn('POST /mcp/message called without sessionId');
        return res.status(400).send('Missing sessionId');
      }

      const session = mcpSessions.get(sessionId);
      if (!session) {
        logger.warn({ sessionId, activeSessions: Array.from(mcpSessions.keys()) }, 'Session not found');
        return res.status(404).send('Session not found');
      }

      logger.info({
        sessionId,
        contentType: req.headers['content-type'],
        contentLength: req.headers['content-length']
      }, 'Received MCP message');

      // Let the transport handle the POST message (it will read the raw body)
      try {
        await session.transport.handlePostMessage(req, res);
        logger.debug({ sessionId }, 'MCP message handled successfully');
      } catch (transportError) {
        logger.error({
          error: transportError,
          sessionId,
          errorMessage: transportError instanceof Error ? transportError.message : 'Unknown error',
          errorStack: transportError instanceof Error ? transportError.stack : undefined
        }, 'Transport handlePostMessage failed');
        throw transportError;
      }
    } catch (error) {
      logger.error({ error }, 'Error processing MCP message');
      if (!res.headersSent) {
        res.status(500).send('Error processing message');
      }
    }
  });

  // Error handling middleware
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    logger.error({ error: err, path: req.path }, 'Unhandled error');

    res.status(500).json({
      error: 'Internal server error',
      message: config.nodeEnv === 'development' ? err.message : 'An unexpected error occurred',
    });
  });

  return app;
}
