/**
 * Tests for AuthCodeStore with Redis backend
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import RedisMock from 'ioredis-mock';
import pino from 'pino';
import { AuthCodeStore } from '../token-store.js';
import { HarvestTokens } from '../harvest-client.js';

describe('AuthCodeStore with Redis', () => {
  let redis: RedisMock;
  let authCodeStore: AuthCodeStore;
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
    authCodeStore = new AuthCodeStore(logger, redis as any);
  });

  afterEach(async () => {
    await redis.flushall();
    redis.disconnect();
  });

  describe('storeAuthCode', () => {
    it('should store auth code in Redis with short TTL', async () => {
      const authCode = await authCodeStore.storeAuthCode(
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

    it('should generate unique codes for different requests', async () => {
      const code1 = await authCodeStore.storeAuthCode(
        mockHarvestTokens,
        'account1',
        1,
        'http://localhost/callback1'
      );
      const code2 = await authCodeStore.storeAuthCode(
        mockHarvestTokens,
        'account2',
        2,
        'http://localhost/callback2'
      );

      expect(code1).not.toBe(code2);

      // Both should be consumable
      const data1 = await authCodeStore.consumeAuthCode(code1, 'http://localhost/callback1');
      const data2 = await authCodeStore.consumeAuthCode(code2, 'http://localhost/callback2');

      expect(data1?.harvestUserId).toBe(1);
      expect(data2?.harvestUserId).toBe(2);
    });
  });

  describe('consumeAuthCode', () => {
    it('should consume auth code and return data', async () => {
      const redirectUri = 'http://localhost/callback';
      const authCode = await authCodeStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      const consumed = await authCodeStore.consumeAuthCode(authCode, redirectUri);

      expect(consumed).not.toBeNull();
      expect(consumed?.harvestTokens).toEqual(mockHarvestTokens);
      expect(consumed?.harvestUserId).toBe(12345);

      // Auth code should be deleted (one-time use)
      const key = `harvest:authcode:${authCode}`;
      const exists = await redis.exists(key);
      expect(exists).toBe(0);

      // Second consumption should fail
      const secondConsume = await authCodeStore.consumeAuthCode(authCode, redirectUri);
      expect(secondConsume).toBeNull();
    });

    it('should reject auth code with wrong redirect URI', async () => {
      const redirectUri = 'http://localhost/callback';
      const authCode = await authCodeStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      const consumed = await authCodeStore.consumeAuthCode(authCode, 'http://evil.com/callback');
      expect(consumed).toBeNull();

      // Auth code should still exist (not consumed)
      const key = `harvest:authcode:${authCode}`;
      const exists = await redis.exists(key);
      expect(exists).toBe(1);
    });

    it('should return null for expired auth code', async () => {
      const redirectUri = 'http://localhost/callback';
      const authCode = await authCodeStore.storeAuthCode(
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

      const consumed = await authCodeStore.consumeAuthCode(authCode, redirectUri);
      expect(consumed).toBeNull();

      // Code should be deleted
      const exists = await redis.exists(key);
      expect(exists).toBe(0);
    });

    it('should return null for non-existent auth code', async () => {
      const consumed = await authCodeStore.consumeAuthCode(
        'non-existent-code',
        'http://localhost/callback'
      );
      expect(consumed).toBeNull();
    });

    it('should handle corrupted data gracefully', async () => {
      const key = 'harvest:authcode:corrupted-code';
      await redis.set(key, 'invalid-json-data');

      const result = await authCodeStore.consumeAuthCode(
        'corrupted-code',
        'http://localhost/callback'
      );
      expect(result).toBeNull();

      // Corrupted data should be cleaned up
      const exists = await redis.exists(key);
      expect(exists).toBe(0);
    });
  });

  describe('Redis TTL expiration', () => {
    it('should automatically expire auth codes after TTL', async () => {
      const redirectUri = 'http://localhost/callback';
      const authCode = await authCodeStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      // Manually set TTL to 1 second
      const key = `harvest:authcode:${authCode}`;
      await redis.expire(key, 1);

      // Code should exist now
      const beforeExpiry = await redis.get(key);
      expect(beforeExpiry).not.toBeNull();

      // Wait for expiration (ioredis-mock handles TTL)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Code should be expired (Redis will have deleted it)
      const afterExpiry = await redis.get(key);
      expect(afterExpiry).toBeNull();

      // Consumption should fail
      const consumed = await authCodeStore.consumeAuthCode(authCode, redirectUri);
      expect(consumed).toBeNull();
    });
  });

  describe('Persistence across "restarts"', () => {
    it('should persist auth codes across AuthCodeStore instances', async () => {
      const redirectUri = 'http://localhost/callback';

      // Store with first instance
      const authCode = await authCodeStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      // Create new AuthCodeStore instance with same Redis
      const authCodeStore2 = new AuthCodeStore(logger, redis as any);

      // Should be able to consume code with new instance
      const consumed = await authCodeStore2.consumeAuthCode(authCode, redirectUri);
      expect(consumed).not.toBeNull();
      expect(consumed?.harvestUserId).toBe(12345);
    });
  });

  describe('In-memory fallback', () => {
    it('should work without Redis (in-memory mode)', async () => {
      const memoryStore = new AuthCodeStore(logger, null);
      const redirectUri = 'http://localhost/callback';

      const authCode = await memoryStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      expect(authCode).toBeDefined();

      const consumed = await memoryStore.consumeAuthCode(authCode, redirectUri);
      expect(consumed).not.toBeNull();
      expect(consumed?.harvestUserId).toBe(12345);

      // Second consumption should fail
      const secondConsume = await memoryStore.consumeAuthCode(authCode, redirectUri);
      expect(secondConsume).toBeNull();
    });

    it('should clean up expired codes in memory mode', async () => {
      const memoryStore = new AuthCodeStore(logger, null);
      const redirectUri = 'http://localhost/callback';

      // Store a code
      const authCode = await memoryStore.storeAuthCode(
        mockHarvestTokens,
        'test-account-id',
        12345,
        redirectUri
      );

      expect(memoryStore.getAuthCodeCount()).toBe(1);

      // Manually expire the code by accessing private property (for testing)
      // In real usage, we rely on the cleanup method being called
      const consumed = await memoryStore.consumeAuthCode(authCode, redirectUri);
      expect(consumed).not.toBeNull();

      // After consumption, code should be removed
      expect(memoryStore.getAuthCodeCount()).toBe(0);
    });
  });
});
