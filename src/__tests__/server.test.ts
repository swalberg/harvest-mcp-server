/**
 * Integration tests for Express server endpoints
 */
import { describe, it, expect, beforeAll, afterEach, beforeEach } from '@jest/globals';
import request from 'supertest';
import nock from 'nock';
import { Express } from 'express';
import { createApp } from '../app.js';
import { Config } from '../config.js';
import pino from 'pino';

describe('Server Integration Tests', () => {
  let app: Express;
  let config: Config;
  let logger: pino.Logger;

  beforeAll(() => {
    // Set up test configuration
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

  describe('GET /health', () => {
    it('should return healthy status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'healthy',
        version: '0.2.0',
      });
      expect(response.body.timestamp).toBeDefined();
    });
  });

  describe('GET /', () => {
    it('should return server info when not authenticated', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);

      expect(response.body).toMatchObject({
        name: 'Harvest MCP Server',
        version: '0.2.0',
        authenticated: false,
        endpoints: {
          auth: '/auth/harvest',
          logout: '/auth/logout',
          mcp: '/mcp',
          health: '/health',
        },
      });
      expect(response.body.user).toBeUndefined();
    });
  });

  describe('GET /auth/harvest', () => {
    it('should redirect to Harvest OAuth authorization URL', async () => {
      const response = await request(app)
        .get('/auth/harvest')
        .expect(302);

      expect(response.headers.location).toContain('https://id.getharvest.com/oauth2/authorize');
      expect(response.headers.location).toContain('client_id=test-client-id');
      expect(response.headers.location).toContain('response_type=code');
      expect(response.headers.location).toContain('state=');
    });
  });

  describe('GET /auth/callback', () => {
    it('should reject callback with invalid state', async () => {
      const response = await request(app)
        .get('/auth/callback?code=test-code&state=invalid-state')
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'Invalid state parameter',
        message: 'Invalid or expired state token. Please try again.',
      });
    });

    it('should handle OAuth errors', async () => {
      const response = await request(app)
        .get('/auth/callback?error=access_denied')
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'OAuth authorization failed',
        message: 'access_denied',
      });
    });

    it('should exchange code for tokens and authenticate user', async () => {
      const agent = request.agent(app);

      // First, initiate OAuth to set state in session
      const authResponse = await agent.get('/auth/harvest');
      const location = authResponse.headers.location;
      const stateMatch = location?.match(/state=([^&]+)/);
      const state = stateMatch ? stateMatch[1] : '';

      // Mock OAuth token exchange
      const mockTokenResponse = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      const mockAccountsResponse = {
        accounts: [{ id: 12345, name: 'Test Account' }],
      };

      const mockUserResponse = {
        id: 67890,
        email: 'test@example.com',
        first_name: 'Test',
        last_name: 'User',
      };

      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, mockTokenResponse);

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, mockAccountsResponse);

      nock('https://api.harvestapp.com')
        .get('/v2/users/me')
        .reply(200, mockUserResponse);

      // Complete the callback with the same state
      const response = await agent
        .get(`/auth/callback?code=test-code&state=${state}`)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        message: 'Authentication successful',
        user: {
          id: 67890,
          email: 'test@example.com',
          name: 'Test User',
        },
      });

      // Verify we're now authenticated
      const statusResponse = await agent.get('/').expect(200);
      expect(statusResponse.body.authenticated).toBe(true);
      expect(statusResponse.body.user).toEqual({ id: 67890 });
    });
  });

  describe('POST /auth/logout', () => {
    it('should logout user and destroy session', async () => {
      const response = await request(app)
        .post('/auth/logout')
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        message: 'Logged out successfully',
      });
    });
  });

  describe('GET /mcp', () => {
    it('should reject unauthenticated requests', async () => {
      const response = await request(app)
        .get('/mcp')
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Not authenticated',
        message: 'Please authenticate with Harvest first',
      });
    });

    // TODO: Update this test for SSE transport (GET /mcp instead of POST /mcp)
    it.skip('should process authenticated MCP requests', async () => {
      const agent = request.agent(app);

      // Authenticate first
      const authResponse = await agent.get('/auth/harvest');
      const location = authResponse.headers.location;
      const stateMatch = location?.match(/state=([^&]+)/);
      const state = stateMatch ? stateMatch[1] : '';

      // Mock OAuth flow
      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, {
          access_token: 'test-token',
          refresh_token: 'test-refresh',
          expires_in: 3600,
          token_type: 'Bearer',
        });

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, { accounts: [{ id: 12345 }] });

      nock('https://api.harvestapp.com')
        .get('/v2/users/me')
        .reply(200, {
          id: 67890,
          email: 'test@example.com',
          first_name: 'Test',
          last_name: 'User',
        });

      await agent.get(`/auth/callback?code=test-code&state=${state}`);

      // Now test MCP endpoint
      const response = await agent
        .post('/mcp')
        .send({
          jsonrpc: '2.0',
          method: 'tools/list',
          id: 1,
        })
        .expect(200);

      expect(response.body).toHaveProperty('tools');
      expect(Array.isArray(response.body.tools)).toBe(true);
      expect(response.body.tools.length).toBeGreaterThan(0);

      // Verify tool names
      const toolNames = response.body.tools.map((t: any) => t.name);
      expect(toolNames).toContain('log_time');
      expect(toolNames).toContain('list_projects');
      expect(toolNames).toContain('list_entries');
    });

    // TODO: Update this test for SSE transport
    it.skip('should return 500 on server error', async () => {
      const agent = request.agent(app);

      // Authenticate first
      const authResponse = await agent.get('/auth/harvest');
      const location = authResponse.headers.location;
      const stateMatch = location?.match(/state=([^&]+)/);
      const state = stateMatch ? stateMatch[1] : '';

      // Mock OAuth flow
      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, {
          access_token: 'test-token',
          refresh_token: 'test-refresh',
          expires_in: 3600,
          token_type: 'Bearer',
        });

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, { accounts: [{ id: 12345 }] });

      nock('https://api.harvestapp.com')
        .get('/v2/users/me')
        .reply(200, {
          id: 67890,
          email: 'test@example.com',
          first_name: 'Test',
          last_name: 'User',
        });

      await agent.get(`/auth/callback?code=test-code&state=${state}`);

      // Mock a Harvest API failure that will cause tools/call to throw an error
      nock('https://api.harvestapp.com')
        .post('/v2/time_entries')
        .replyWithError('Network error');

      // Send a tools/call request that will trigger the error
      const response = await agent
        .post('/mcp')
        .send({
          jsonrpc: '2.0',
          method: 'tools/call',
          id: 1,
          params: {
            name: 'log_time',
            arguments: {
              text: '2 hours on Test Project doing testing',
            },
          },
        })
        .expect(500);

      expect(response.body).toMatchObject({
        error: 'MCP request failed',
      });
      expect(response.body).toHaveProperty('message');
    });
  });
});
