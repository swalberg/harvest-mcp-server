/**
 * Tests for OAuth service
 */
import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import nock from 'nock';
import { OAuthService } from '../oauth.js';
import { Config } from '../config.js';
import pino from 'pino';

describe('OAuthService', () => {
  let oauthService: OAuthService;
  let mockConfig: Config;
  let mockLogger: pino.Logger;

  beforeEach(() => {
    mockConfig = {
      harvestOAuthClientId: 'test-client-id',
      harvestOAuthClientSecret: 'test-client-secret',
      oauthRedirectUri: 'http://localhost:3000/auth/callback',
      serverBaseUrl: 'http://localhost:3000',
      sessionSecret: 'test-secret',
      port: 3000,
      nodeEnv: 'test',
      standardWorkDayHours: 7.5,
      timezone: 'Australia/Perth',
      logLevel: 'silent',
    };

    mockLogger = pino({ level: 'silent' });
    oauthService = new OAuthService(mockConfig, mockLogger);

    // Clear all nock interceptors
    nock.cleanAll();
  });

  describe('getAuthorizationUrl', () => {
    it('should generate correct authorization URL', () => {
      const state = 'test-state-123';
      const url = oauthService.getAuthorizationUrl(state);

      expect(url).toContain('https://id.getharvest.com/oauth2/authorize');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback');
      expect(url).toContain('state=test-state-123');
      expect(url).toContain('response_type=code');
    });
  });

  describe('exchangeCodeForToken', () => {
    it('should exchange authorization code for access token', async () => {
      const mockTokenResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      const mockAccountsResponse = {
        accounts: [
          {
            id: 12345,
            name: 'Test Account',
          },
        ],
      };

      // Mock the token exchange (expects form-urlencoded)
      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, mockTokenResponse);

      // Mock the accounts request
      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, mockAccountsResponse);

      const result = await oauthService.exchangeCodeForToken('test-code');

      expect(result.access_token).toBe('mock-access-token');
      expect(result.refresh_token).toBe('mock-refresh-token');
      expect(result.expires_in).toBe(3600);
      expect(result.token_type).toBe('Bearer');
      expect(result.account_id).toBe('12345');
    });

    it('should throw error on invalid authorization code', async () => {
      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(400, {
          error: 'invalid_grant',
          error_description: 'The provided authorization grant is invalid',
        });

      await expect(oauthService.exchangeCodeForToken('invalid-code')).rejects.toThrow(
        'OAuth token exchange failed'
      );
    });

    it('should throw error when no accounts found', async () => {
      const mockTokenResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, mockTokenResponse);

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, { accounts: [] });

      await expect(oauthService.exchangeCodeForToken('test-code')).rejects.toThrow(
        'No Harvest accounts found for this user'
      );
    });
  });

  describe('refreshAccessToken', () => {
    it('should refresh access token successfully', async () => {
      const mockTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      const mockAccountsResponse = {
        accounts: [
          {
            id: 12345,
            name: 'Test Account',
          },
        ],
      };

      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(200, mockTokenResponse);

      nock('https://id.getharvest.com')
        .get('/api/v2/accounts')
        .reply(200, mockAccountsResponse);

      const result = await oauthService.refreshAccessToken('old-refresh-token');

      expect(result.access_token).toBe('new-access-token');
      expect(result.refresh_token).toBe('new-refresh-token');
      expect(result.expires_in).toBe(3600);
      expect(result.account_id).toBe('12345');
    });

    it('should throw error on invalid refresh token', async () => {
      nock('https://id.getharvest.com')
        .post('/api/v2/oauth2/token')
        .reply(400, {
          error: 'invalid_grant',
          error_description: 'The provided refresh token is invalid',
        });

      await expect(oauthService.refreshAccessToken('invalid-token')).rejects.toThrow(
        'Token refresh failed'
      );
    });
  });
});
