/**
 * Tests for TokenStore with Redis backend
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import RedisMock from 'ioredis-mock';
import pino from 'pino';
import { TokenStore } from '../token-store.js';
import { HarvestTokens } from '../harvest-client.js';

describe('TokenStore with Redis', () => {
  let redis: RedisMock;
  let tokenStore: TokenStore;
  let logger: pino.Logger;

  const mockHarvestTokens: HarvestTokens = {
    access_token: 'mock-harvest-access-token',
    refresh_token: 'mock-harvest-refresh-token',
    expires_in: 64800,
    token_type: 'Bearer',
  };

  beforeEach(() => {
    logger = pino({ level: 'silent' });
    redis = new RedisMock();
    tokenStore = new TokenStore(logger, redis as any);
  });

  afterEach(async () => {
    await redis.flushall();
    redis.disconnect();
  });

  describe('storeToken', () => {
    it('should store token in Redis with TTL', async () => {
      const accessToken = await tokenStore.storeToken(
        mockHarvestTokens,
        'test-account-id',
        12345
      );

      expect(accessToken).toBeDefined();
      expect(accessToken.length).toBe(64); // 32 bytes in hex = 64 chars

      // Verify token exists in Redis
      const key = `harvest:token:${accessToken}`;
      const data = await redis.get(key);
      expect(data).not.toBeNull();

      const stored = JSON.parse(data!);
      expect(stored.harvestTokens).toEqual(mockHarvestTokens);
      expect(stored.harvestAccountId).toBe('test-account-id');
      expect(stored.harvestUserId).toBe(12345);

      // Verify TTL is set (should be close to 7 days in seconds)
      const ttl = await redis.ttl(key);
      expect(ttl).toBeGreaterThan(7 * 24 * 60 * 60 - 10); // Allow 10 second margin
      expect(ttl).toBeLessThanOrEqual(7 * 24 * 60 * 60);
    });

    it('should generate unique tokens for different users', async () => {
      const token1 = await tokenStore.storeToken(mockHarvestTokens, 'account1', 1);
      const token2 = await tokenStore.storeToken(mockHarvestTokens, 'account2', 2);

      expect(token1).not.toBe(token2);

      // Both should be retrievable
      const data1 = await tokenStore.getToken(token1);
      const data2 = await tokenStore.getToken(token2);

      expect(data1?.harvestUserId).toBe(1);
      expect(data2?.harvestUserId).toBe(2);
    });
  });

  describe('getToken', () => {
    it('should retrieve stored token from Redis', async () => {
      const accessToken = await tokenStore.storeToken(
        mockHarvestTokens,
        'test-account-id',
        12345
      );

      const retrieved = await tokenStore.getToken(accessToken);

      expect(retrieved).not.toBeNull();
      expect(retrieved?.accessToken).toBe(accessToken);
      expect(retrieved?.harvestTokens).toEqual(mockHarvestTokens);
      expect(retrieved?.harvestAccountId).toBe('test-account-id');
      expect(retrieved?.harvestUserId).toBe(12345);
    });

    it('should return null for non-existent token', async () => {
      const result = await tokenStore.getToken('non-existent-token');
      expect(result).toBeNull();
    });

    it('should return null for expired token', async () => {
      const accessToken = await tokenStore.storeToken(
        mockHarvestTokens,
        'test-account-id',
        12345
      );

      // Manually set expiration to past
      const key = `harvest:token:${accessToken}`;
      const data = await redis.get(key);
      const tokenData = JSON.parse(data!);
      tokenData.expiresAt = Date.now() - 1000; // Expired 1 second ago
      await redis.set(key, JSON.stringify(tokenData));

      const result = await tokenStore.getToken(accessToken);
      expect(result).toBeNull();

      // Token should be deleted from Redis
      const exists = await redis.exists(key);
      expect(exists).toBe(0);
    });

    it('should handle corrupted data gracefully', async () => {
      const key = 'harvest:token:corrupted-token';
      await redis.set(key, 'invalid-json-data');

      const result = await tokenStore.getToken('corrupted-token');
      expect(result).toBeNull();
    });
  });

  describe('revokeToken', () => {
    it('should revoke token from Redis', async () => {
      const accessToken = await tokenStore.storeToken(
        mockHarvestTokens,
        'test-account-id',
        12345
      );

      const revoked = await tokenStore.revokeToken(accessToken);
      expect(revoked).toBe(true);

      // Token should no longer exist
      const result = await tokenStore.getToken(accessToken);
      expect(result).toBeNull();
    });

    it('should return false when revoking non-existent token', async () => {
      const revoked = await tokenStore.revokeToken('non-existent-token');
      expect(revoked).toBe(false);
    });
  });

  describe('storeAuthCode', () => {
    it('should store auth code in Redis with short TTL', async () => {
      const authCode = await tokenStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        'http://localhost/callback'
      );

      expect(authCode).toBeDefined();
      expect(authCode.length).toBe(64);

      // Verify auth code exists in Redis
      const key = `harvest:authcode:${authCode}`;
      const data = await redis.get(key);
      expect(data).not.toBeNull();

      const stored = JSON.parse(data!);
      expect(stored.harvestTokens).toEqual(mockHarvestTokens);
      expect(stored.redirectUri).toBe('http://localhost/callback');

      // Verify TTL is set (should be close to 5 minutes)
      const ttl = await redis.ttl(key);
      expect(ttl).toBeGreaterThan(5 * 60 - 10); // Allow 10 second margin
      expect(ttl).toBeLessThanOrEqual(5 * 60);
    });
  });

  describe('consumeAuthCode', () => {
    it('should consume auth code and return data', async () => {
      const redirectUri = 'http://localhost/callback';
      const authCode = await tokenStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      const consumed = await tokenStore.consumeAuthCode(authCode, redirectUri);

      expect(consumed).not.toBeNull();
      expect(consumed?.harvestTokens).toEqual(mockHarvestTokens);
      expect(consumed?.harvestUserId).toBe(12345);

      // Auth code should be deleted (one-time use)
      const key = `harvest:authcode:${authCode}`;
      const exists = await redis.exists(key);
      expect(exists).toBe(0);

      // Second consumption should fail
      const secondConsume = await tokenStore.consumeAuthCode(authCode, redirectUri);
      expect(secondConsume).toBeNull();
    });

    it('should reject auth code with wrong redirect URI', async () => {
      const redirectUri = 'http://localhost/callback';
      const authCode = await tokenStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      const consumed = await tokenStore.consumeAuthCode(authCode, 'http://evil.com/callback');
      expect(consumed).toBeNull();

      // Auth code should still exist (not consumed)
      const key = `harvest:authcode:${authCode}`;
      const exists = await redis.exists(key);
      expect(exists).toBe(1);
    });

    it('should return null for expired auth code', async () => {
      const redirectUri = 'http://localhost/callback';
      const authCode = await tokenStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      // Manually set expiration to past
      const key = `harvest:authcode:${authCode}`;
      const data = await redis.get(key);
      const codeData = JSON.parse(data!);
      codeData.expiresAt = Date.now() - 1000;
      await redis.set(key, JSON.stringify(codeData));

      const consumed = await tokenStore.consumeAuthCode(authCode, redirectUri);
      expect(consumed).toBeNull();

      // Code should be deleted
      const exists = await redis.exists(key);
      expect(exists).toBe(0);
    });
  });

  describe('Redis TTL expiration', () => {
    it('should automatically expire tokens after TTL', async () => {
      // Store a token with very short TTL for testing
      const accessToken = await tokenStore.storeToken(
        mockHarvestTokens,
        'test-account-id',
        12345
      );

      // Manually set TTL to 1 second
      const key = `harvest:token:${accessToken}`;
      await redis.expire(key, 1);

      // Token should exist now
      const beforeExpiry = await tokenStore.getToken(accessToken);
      expect(beforeExpiry).not.toBeNull();

      // Wait for expiration (ioredis-mock handles TTL)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Token should be expired (Redis will have deleted it)
      const afterExpiry = await redis.get(key);
      expect(afterExpiry).toBeNull();
    });
  });

  describe('Persistence across "restarts"', () => {
    it('should persist tokens across TokenStore instances', async () => {
      // Store with first instance
      const accessToken = await tokenStore.storeToken(
        mockHarvestTokens,
        'test-account-id',
        12345
      );

      // Create new TokenStore instance with same Redis
      const tokenStore2 = new TokenStore(logger, redis as any);

      // Should be able to retrieve token with new instance
      const retrieved = await tokenStore2.getToken(accessToken);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.harvestUserId).toBe(12345);
    });
  });
});
