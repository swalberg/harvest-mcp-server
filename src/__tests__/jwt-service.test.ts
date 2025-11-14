/**
 * Tests for JWT service
 */
import { JwtService } from '../jwt-service';
import { HarvestTokens } from '../harvest-client';
import jwt from 'jsonwebtoken';
import pino from 'pino';

describe('JwtService', () => {
  let jwtService: JwtService;
  let logger: pino.Logger;
  const secret = 'test-secret-key-for-jwt';
  const mockHarvestTokens: HarvestTokens = {
    access_token: 'harvest_access_token_abc123',
    refresh_token: 'harvest_refresh_token_xyz789',
    expires_in: 64800,
    token_type: 'bearer',
  };
  const accountId = 'test-account-123';
  const userId = 12345;

  beforeEach(() => {
    logger = pino({ level: 'silent' });
    jwtService = new JwtService(secret, logger);
  });

  describe('generateToken', () => {
    it('should generate a valid JWT token', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT format: header.payload.signature
    });

    it('should include user metadata in token payload', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const decoded = jwt.decode(token) as any;

      expect(decoded).toBeDefined();
      expect(decoded.sub).toBe(userId.toString());
      expect(decoded.accountId).toBe(accountId);
      expect(decoded.userId).toBe(userId);
      expect(decoded.encryptedTokens).toBeDefined();
      expect(decoded.iat).toBeDefined();
      expect(decoded.exp).toBeDefined();
    });

    it('should set expiration to 7 days by default', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const decoded = jwt.decode(token) as any;

      const expectedExpiration = 7 * 24 * 60 * 60; // 7 days in seconds
      const actualExpiration = decoded.exp - decoded.iat;

      expect(actualExpiration).toBe(expectedExpiration);
    });

    it('should respect custom expiration days', () => {
      const customDays = 30;
      const customJwtService = new JwtService(secret, logger, customDays);
      const token = customJwtService.generateToken(mockHarvestTokens, accountId, userId);
      const decoded = jwt.decode(token) as any;

      const expectedExpiration = customDays * 24 * 60 * 60;
      const actualExpiration = decoded.exp - decoded.iat;

      expect(actualExpiration).toBe(expectedExpiration);
    });

    it('should encrypt Harvest tokens in payload', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const decoded = jwt.decode(token) as any;

      // Encrypted tokens should be base64 string
      expect(typeof decoded.encryptedTokens).toBe('string');
      expect(decoded.encryptedTokens).not.toContain(mockHarvestTokens.access_token);
      expect(decoded.encryptedTokens).not.toContain(mockHarvestTokens.refresh_token);
    });
  });

  describe('verifyToken', () => {
    it('should verify and decode a valid token', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.userId).toBe(userId);
      expect(decoded!.accountId).toBe(accountId);
      expect(decoded!.harvestTokens).toEqual(mockHarvestTokens);
    });

    it('should return null for invalid token', () => {
      const invalidToken = 'invalid.jwt.token';
      const decoded = jwtService.verifyToken(invalidToken);

      expect(decoded).toBeNull();
    });

    it('should return null for expired token', () => {
      // Create a JWT service with very short expiration
      const shortLivedService = new JwtService(secret, logger, 0);
      const token = shortLivedService.generateToken(mockHarvestTokens, accountId, userId);

      // Wait a bit to let it expire (token expires immediately with 0 days)
      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeNull();
    });

    it('should return null for token signed with different secret', () => {
      const differentSecret = 'different-secret-key';
      const differentService = new JwtService(differentSecret, logger);
      const token = differentService.generateToken(mockHarvestTokens, accountId, userId);

      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeNull();
    });

    it('should decrypt Harvest tokens correctly', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.harvestTokens.access_token).toBe(mockHarvestTokens.access_token);
      expect(decoded!.harvestTokens.refresh_token).toBe(mockHarvestTokens.refresh_token);
      expect(decoded!.harvestTokens.expires_in).toBe(mockHarvestTokens.expires_in);
      expect(decoded!.harvestTokens.token_type).toBe(mockHarvestTokens.token_type);
    });

    it('should handle tokens with special characters in Harvest credentials', () => {
      const specialTokens: HarvestTokens = {
        access_token: 'token-with-special-chars!@#$%^&*()_+-=[]{}|;:,.<>?',
        refresh_token: 'refresh🚀with💡emoji',
        expires_in: 64800,
        token_type: 'bearer',
      };

      const token = jwtService.generateToken(specialTokens, accountId, userId);
      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.harvestTokens).toEqual(specialTokens);
    });
  });

  describe('decodeToken', () => {
    it('should decode token without verification', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const decoded = jwtService.decodeToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.sub).toBe(userId.toString());
      expect(decoded!.accountId).toBe(accountId);
      expect(decoded!.userId).toBe(userId);
    });

    it('should decode expired token', () => {
      const shortLivedService = new JwtService(secret, logger, 0);
      const token = shortLivedService.generateToken(mockHarvestTokens, accountId, userId);

      const decoded = jwtService.decodeToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.userId).toBe(userId);
    });

    it('should return null for malformed token', () => {
      const decoded = jwtService.decodeToken('not-a-jwt-token');

      expect(decoded).toBeNull();
    });
  });

  describe('getTokenTtl', () => {
    it('should return remaining TTL for valid token', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const ttl = jwtService.getTokenTtl(token);

      expect(ttl).toBeDefined();
      expect(ttl!).toBeGreaterThan(0);
      expect(ttl!).toBeLessThanOrEqual(7 * 24 * 60 * 60); // Max 7 days
    });

    it('should return 0 for expired token', () => {
      const shortLivedService = new JwtService(secret, logger, 0);
      const token = shortLivedService.generateToken(mockHarvestTokens, accountId, userId);

      const ttl = jwtService.getTokenTtl(token);

      expect(ttl).toBe(0);
    });

    it('should return null for invalid token', () => {
      const ttl = jwtService.getTokenTtl('invalid-token');

      expect(ttl).toBeNull();
    });

    it('should return decreasing TTL over time', async () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const ttl1 = jwtService.getTokenTtl(token);

      // Wait 1 second
      await new Promise(resolve => setTimeout(resolve, 1000));

      const ttl2 = jwtService.getTokenTtl(token);

      expect(ttl2).toBeLessThan(ttl1!);
    });
  });

  describe('encryption security', () => {
    it('should use different encryption for each token', () => {
      const token1 = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const token2 = jwtService.generateToken(mockHarvestTokens, accountId, userId);

      const decoded1 = jwt.decode(token1) as any;
      const decoded2 = jwt.decode(token2) as any;

      // Even with same inputs, encrypted data should differ due to random IV
      expect(decoded1.encryptedTokens).not.toBe(decoded2.encryptedTokens);
    });

    it('should not be decryptable with different secret', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);

      const differentService = new JwtService('different-secret', logger);
      const decoded = differentService.verifyToken(token);

      expect(decoded).toBeNull();
    });

    it('should protect against token tampering', () => {
      const token = jwtService.generateToken(mockHarvestTokens, accountId, userId);
      const parts = token.split('.');

      // Tamper with payload
      const tamperedPayload = Buffer.from(
        JSON.stringify({ ...jwt.decode(token), userId: 99999 })
      ).toString('base64');
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      const decoded = jwtService.verifyToken(tamperedToken);

      expect(decoded).toBeNull();
    });
  });

  describe('edge cases', () => {
    it('should handle empty strings in Harvest tokens', () => {
      const emptyTokens: HarvestTokens = {
        access_token: '',
        refresh_token: '',
        expires_in: 0,
        token_type: '',
      };

      const token = jwtService.generateToken(emptyTokens, '', 0);
      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.harvestTokens).toEqual(emptyTokens);
    });

    it('should handle very large user IDs', () => {
      const largeUserId = 9007199254740991; // Max safe integer in JS
      const token = jwtService.generateToken(mockHarvestTokens, accountId, largeUserId);
      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.userId).toBe(largeUserId);
    });

    it('should handle long account IDs', () => {
      const longAccountId = 'a'.repeat(1000);
      const token = jwtService.generateToken(mockHarvestTokens, longAccountId, userId);
      const decoded = jwtService.verifyToken(token);

      expect(decoded).toBeDefined();
      expect(decoded!.accountId).toBe(longAccountId);
    });
  });
});
