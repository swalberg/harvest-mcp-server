/**
 * Tests for configuration module
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { loadConfig } from '../config.js';

describe('Configuration', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset process.env before each test
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('loadConfig', () => {
    it('should load all required environment variables', () => {
      process.env.HARVEST_OAUTH_CLIENT_ID = 'test-client-id';
      process.env.HARVEST_OAUTH_CLIENT_SECRET = 'test-client-secret';
      process.env.OAUTH_REDIRECT_URI = 'http://localhost:3000/auth/callback';
      process.env.SESSION_SECRET = 'test-session-secret';

      const config = loadConfig();

      expect(config.harvestOAuthClientId).toBe('test-client-id');
      expect(config.harvestOAuthClientSecret).toBe('test-client-secret');
      expect(config.oauthRedirectUri).toBe('http://localhost:3000/auth/callback');
      expect(config.sessionSecret).toBe('test-session-secret');
    });

    it('should throw error when required variable is missing', () => {
      delete process.env.HARVEST_OAUTH_CLIENT_ID;

      expect(() => loadConfig()).toThrow('Required environment variable HARVEST_OAUTH_CLIENT_ID is not set');
    });

    it('should use default values for optional variables', () => {
      process.env.HARVEST_OAUTH_CLIENT_ID = 'test-client-id';
      process.env.HARVEST_OAUTH_CLIENT_SECRET = 'test-client-secret';
      process.env.OAUTH_REDIRECT_URI = 'http://localhost:3000/auth/callback';
      process.env.SESSION_SECRET = 'test-session-secret';
      delete process.env.NODE_ENV;
      delete process.env.PORT;
      delete process.env.STANDARD_WORK_DAY_HOURS;
      delete process.env.TIMEZONE;
      delete process.env.LOG_LEVEL;

      const config = loadConfig();

      expect(config.port).toBe(3000);
      expect(config.nodeEnv).toBe('development');
      expect(config.standardWorkDayHours).toBe(7.5);
      expect(config.timezone).toBe('Australia/Perth');
      expect(config.logLevel).toBe('info');
    });

    it('should override defaults with provided values', () => {
      process.env.HARVEST_OAUTH_CLIENT_ID = 'test-client-id';
      process.env.HARVEST_OAUTH_CLIENT_SECRET = 'test-client-secret';
      process.env.OAUTH_REDIRECT_URI = 'http://localhost:3000/auth/callback';
      process.env.SESSION_SECRET = 'test-session-secret';
      process.env.PORT = '8080';
      process.env.NODE_ENV = 'production';
      process.env.STANDARD_WORK_DAY_HOURS = '8.0';
      process.env.TIMEZONE = 'America/New_York';
      process.env.LOG_LEVEL = 'debug';

      const config = loadConfig();

      expect(config.port).toBe(8080);
      expect(config.nodeEnv).toBe('production');
      expect(config.standardWorkDayHours).toBe(8.0);
      expect(config.timezone).toBe('America/New_York');
      expect(config.logLevel).toBe('debug');
    });
  });
});
