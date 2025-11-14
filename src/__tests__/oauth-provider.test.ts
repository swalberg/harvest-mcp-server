/**
 * Tests for OAuth provider endpoints
 */
import { describe, it, expect, beforeAll, afterEach } from '@jest/globals';
import request from 'supertest';
import nock from 'nock';
import { Express } from 'express';
import { createApp } from '../app.js';
import { Config } from '../config.js';
import pino from 'pino';

describe('OAuth Provider Endpoints', () => {
  let app: Express;
  let config: Config;
  let logger: pino.Logger;

  beforeAll(() => {
    config = {
      harvestOAuthClientId: 'test-client-id',
      harvestOAuthClientSecret: 'test-client-secret',
      oauthRedirectUri: 'http://localhost:3000/auth/callback',
      serverBaseUrl: 'http://localhost:3001',
      sessionSecret: 'test-session-secret',
      port: 3001,
      nodeEnv: 'test',
      standardWorkDayHours: 7.5,
      timezone: 'Australia/Perth',
      logLevel: 'silent',
    };

    logger = pino({ level: 'silent' });
    app = createApp(config, logger);
  });

  afterEach(() => {
    nock.cleanAll();
  });

  describe('GET /.well-known/oauth-authorization-server', () => {
    it('should return OAuth discovery metadata', async () => {
      const response = await request(app)
        .get('/.well-known/oauth-authorization-server')
        .expect(200);

      expect(response.body).toMatchObject({
        issuer: 'http://localhost:3001',
        authorization_endpoint: 'http://localhost:3001/oauth/authorize',
        token_endpoint: 'http://localhost:3001/oauth/token',
        registration_endpoint: 'http://localhost:3001/oauth/register',
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['plain', 'S256'],
      });
    });
  });

  describe('POST /oauth/register', () => {
    it('should register a new client', async () => {
      const response = await request(app)
        .post('/oauth/register')
        .send({
          redirect_uris: ['http://localhost:8080/callback'],
          client_name: 'Test MCP Client',
        })
        .expect(201);

      expect(response.body).toMatchObject({
        client_name: 'Test MCP Client',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_post',
      });
      expect(response.body.client_id).toBeTruthy();
      expect(response.body.client_secret).toBeTruthy();
      expect(typeof response.body.client_id).toBe('string');
      expect(typeof response.body.client_secret).toBe('string');
    });

    it('should reject registration without redirect_uris', async () => {
      const response = await request(app)
        .post('/oauth/register')
        .send({
          client_name: 'Test Client',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'invalid_redirect_uri',
        error_description: 'redirect_uris must be a non-empty array',
      });
    });

    it('should reject registration with empty redirect_uris array', async () => {
      const response = await request(app)
        .post('/oauth/register')
        .send({
          redirect_uris: [],
          client_name: 'Test Client',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'invalid_redirect_uri',
        error_description: 'redirect_uris must be a non-empty array',
      });
    });
  });

  describe('GET /oauth/authorize', () => {
    it('should redirect to Harvest OAuth with valid parameters', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost:8080/callback',
          state: 'client-state-123',
          response_type: 'code',
        })
        .expect(302);

      // Should redirect to Harvest OAuth
      expect(response.headers.location).toContain('https://id.getharvest.com/oauth2/authorize');
      expect(response.headers.location).toContain('client_id=test-client-id');
      expect(response.headers.location).toContain('state=');
    });

    it('should reject unsupported response_type', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost:8080/callback',
          state: 'client-state-123',
          response_type: 'token',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'unsupported_response_type',
        error_description: 'Only response_type=code is supported',
      });
    });
  });

  describe('POST /oauth/token', () => {
    it('should reject requests without authorization code', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          redirect_uri: 'http://localhost:8080/callback',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'invalid_request',
        error_description: 'Missing code parameter',
      });
    });

    it('should reject unsupported grant_type', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          code: 'test-code',
          redirect_uri: 'http://localhost:8080/callback',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'unsupported_grant_type',
        error_description: 'Only grant_type=authorization_code is supported',
      });
    });

    it('should reject invalid authorization code', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: 'invalid-code',
          redirect_uri: 'http://localhost:8080/callback',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code',
      });
    });

    it('should exchange valid authorization code for access token', async () => {
      const agent = request.agent(app);
      const mcpClientRedirectUri = 'http://localhost:8080/callback';

      // Step 1: MCP client initiates OAuth flow
      const authResponse = await agent
        .get('/oauth/authorize')
        .query({
          client_id: 'mcp-client',
          redirect_uri: mcpClientRedirectUri,
          state: 'client-state-123',
          response_type: 'code',
        })
        .expect(302);

      // Extract state from Harvest redirect
      const harvestAuthUrl = authResponse.headers.location;
      const stateMatch = harvestAuthUrl.match(/state=([^&]+)/);
      const harvestState = stateMatch ? stateMatch[1] : '';

      // Step 2: Mock Harvest OAuth flow
      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, {
          access_token: 'harvest-access-token',
          refresh_token: 'harvest-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
        });

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, {
          accounts: [{ id: 12345, name: 'Test Account' }],
        });

      nock('https://api.harvestapp.com')
        .get('/v2/users/me')
        .reply(200, {
          id: 67890,
          email: 'test@example.com',
          first_name: 'Test',
          last_name: 'User',
        });

      // Step 3: Complete Harvest callback - should redirect to MCP client
      const callbackResponse = await agent
        .get('/auth/callback')
        .query({
          code: 'harvest-auth-code',
          state: harvestState,
        })
        .expect(302);

      // Should redirect back to MCP client with authorization code
      const redirectUrl = new URL(callbackResponse.headers.location);
      expect(redirectUrl.origin + redirectUrl.pathname).toBe(mcpClientRedirectUri);

      const authCode = redirectUrl.searchParams.get('code');
      const returnedState = redirectUrl.searchParams.get('state');

      expect(authCode).toBeTruthy();
      expect(returnedState).toBe('client-state-123');

      // Step 4: MCP client exchanges authorization code for access token
      const tokenResponse = await agent
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authCode,
          redirect_uri: mcpClientRedirectUri,
        })
        .expect(200);

      expect(tokenResponse.body).toMatchObject({
        token_type: 'Bearer',
        expires_in: 7 * 24 * 60 * 60, // 7 days
      });
      expect(tokenResponse.body.access_token).toBeTruthy();
      expect(typeof tokenResponse.body.access_token).toBe('string');

      // Verify token is in JWT format (header.payload.signature)
      const tokenParts = tokenResponse.body.access_token.split('.');
      expect(tokenParts).toHaveLength(3);
    });

    it('should reject authorization code with mismatched redirect_uri', async () => {
      const agent = request.agent(app);
      const mcpClientRedirectUri = 'http://localhost:8080/callback';

      // Step 1: Initiate OAuth flow
      const authResponse = await agent
        .get('/oauth/authorize')
        .query({
          client_id: 'mcp-client',
          redirect_uri: mcpClientRedirectUri,
          state: 'client-state-123',
          response_type: 'code',
        })
        .expect(302);

      const harvestAuthUrl = authResponse.headers.location;
      const stateMatch = harvestAuthUrl.match(/state=([^&]+)/);
      const harvestState = stateMatch ? stateMatch[1] : '';

      // Step 2: Mock Harvest OAuth flow
      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, {
          access_token: 'harvest-access-token',
          refresh_token: 'harvest-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
        });

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, {
          accounts: [{ id: 12345, name: 'Test Account' }],
        });

      nock('https://api.harvestapp.com')
        .get('/v2/users/me')
        .reply(200, {
          id: 67890,
          email: 'test@example.com',
          first_name: 'Test',
          last_name: 'User',
        });

      // Step 3: Complete callback
      const callbackResponse = await agent
        .get('/auth/callback')
        .query({
          code: 'harvest-auth-code',
          state: harvestState,
        })
        .expect(302);

      const redirectUrl = new URL(callbackResponse.headers.location);
      const authCode = redirectUrl.searchParams.get('code');

      // Step 4: Try to exchange with different redirect_uri
      const tokenResponse = await agent
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authCode,
          redirect_uri: 'http://localhost:9999/different', // Wrong redirect_uri
        })
        .expect(400);

      expect(tokenResponse.body).toMatchObject({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code',
      });
    });
  });

  describe('GET /mcp with Bearer token (SSE)', () => {
    // TODO: Fix SSE test - connection stays open and causes timeout
    it.skip('should establish SSE connection with Bearer token authentication', async () => {
      const agent = request.agent(app);
      const mcpClientRedirectUri = 'http://localhost:8080/callback';

      // Complete OAuth flow to get access token
      const authResponse = await agent
        .get('/oauth/authorize')
        .query({
          client_id: 'mcp-client',
          redirect_uri: mcpClientRedirectUri,
          state: 'client-state-123',
          response_type: 'code',
        })
        .expect(302);

      const harvestAuthUrl = authResponse.headers.location;
      const stateMatch = harvestAuthUrl.match(/state=([^&]+)/);
      const harvestState = stateMatch ? stateMatch[1] : '';

      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, {
          access_token: 'harvest-access-token',
          refresh_token: 'harvest-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
        });

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, {
          accounts: [{ id: 12345, name: 'Test Account' }],
        });

      nock('https://api.harvestapp.com')
        .get('/v2/users/me')
        .reply(200, {
          id: 67890,
          email: 'test@example.com',
          first_name: 'Test',
          last_name: 'User',
        });

      const callbackResponse = await agent
        .get('/auth/callback')
        .query({
          code: 'harvest-auth-code',
          state: harvestState,
        })
        .expect(302);

      const redirectUrl = new URL(callbackResponse.headers.location);
      const authCode = redirectUrl.searchParams.get('code');

      const tokenResponse = await agent
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authCode,
          redirect_uri: mcpClientRedirectUri,
        })
        .expect(200);

      const accessToken = tokenResponse.body.access_token;

      // Now use Bearer token to establish SSE connection
      const mcpResponse = await request(app)
        .get('/mcp')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200)
        .expect('Content-Type', /text\/event-stream/);

      // Verify SSE endpoint event is sent
      expect(mcpResponse.text).toContain('event: endpoint');
      expect(mcpResponse.text).toContain('data: ');
      expect(mcpResponse.text).toContain('/mcp/message?sessionId=');
    });

    it('should reject invalid Bearer token', async () => {
      const response = await request(app)
        .get('/mcp')
        .set('Authorization', 'Bearer invalid-token-12345')
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Invalid or expired access token',
        message: 'Please re-authenticate',
      });
    });

    it('should reject malformed Authorization header', async () => {
      const response = await request(app)
        .get('/mcp')
        .set('Authorization', 'InvalidScheme token-here')
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Not authenticated',
        message: 'Please authenticate with Harvest first',
      });
    });

  });
});
