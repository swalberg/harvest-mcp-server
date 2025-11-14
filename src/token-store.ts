/**
 * Token store for OAuth provider with Redis support
 * Maps local access tokens to Harvest credentials
 * Falls back to in-memory storage if Redis is not available
 */
import { randomBytes } from 'crypto';
import type { Redis } from 'ioredis';
import { HarvestTokens } from './harvest-client.js';
import { Logger } from './logger.js';

export interface StoredToken {
  accessToken: string;
  harvestTokens: HarvestTokens;
  harvestAccountId: string;
  harvestUserId: number;
  expiresAt: number;
  createdAt: number;
}

export interface StoredAuthCode {
  code: string;
  harvestTokens: HarvestTokens;
  harvestAccountId: string;
  harvestUserId: number;
  redirectUri: string;
  expiresAt: number;
  createdAt: number;
}

export class TokenStore {
  private tokens: Map<string, StoredToken> = new Map();
  private authCodes: Map<string, StoredAuthCode> = new Map();
  private logger: Logger;
  private redis: Redis | null;

  constructor(logger: Logger, redis: Redis | null = null) {
    this.logger = logger;
    this.redis = redis;

    if (redis) {
      this.logger.info('TokenStore using Redis for persistence');
    } else {
      this.logger.info('TokenStore using in-memory storage');
    }
  }

  /**
   * Generate a new access token
   */
  generateToken(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Store a new token mapping
   */
  async storeToken(
    harvestTokens: HarvestTokens,
    harvestAccountId: string,
    harvestUserId: number
  ): Promise<string> {
    const accessToken = this.generateToken();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    const tokenData: StoredToken = {
      accessToken,
      harvestTokens,
      harvestAccountId,
      harvestUserId,
      expiresAt,
      createdAt: Date.now(),
    };

    if (this.redis) {
      // Store in Redis with TTL
      const key = `harvest:token:${accessToken}`;
      const ttlSeconds = Math.floor((expiresAt - Date.now()) / 1000);
      await this.redis.setex(key, ttlSeconds, JSON.stringify(tokenData));
    } else {
      // Store in memory
      this.tokens.set(accessToken, tokenData);
    }

    this.logger.info(
      { userId: harvestUserId, tokenPrefix: accessToken.substring(0, 8) },
      'Stored new access token'
    );

    // Clean up expired tokens (in-memory only)
    if (!this.redis) {
      this.cleanupExpiredTokens();
    }

    return accessToken;
  }

  /**
   * Retrieve token data by access token
   */
  async getToken(accessToken: string): Promise<StoredToken | null> {
    if (this.redis) {
      // Get from Redis
      const key = `harvest:token:${accessToken}`;
      const data = await this.redis.get(key);

      if (!data) {
        return null;
      }

      try {
        const token = JSON.parse(data) as StoredToken;

        // Double-check expiration (Redis TTL should handle this, but be defensive)
        if (Date.now() > token.expiresAt) {
          this.logger.info({ tokenPrefix: accessToken.substring(0, 8) }, 'Token expired');
          await this.redis.del(key);
          return null;
        }

        return token;
      } catch (error) {
        this.logger.error({ error }, 'Failed to parse token from Redis');
        return null;
      }
    } else {
      // Get from memory
      const token = this.tokens.get(accessToken);

      if (!token) {
        return null;
      }

      // Check if expired
      if (Date.now() > token.expiresAt) {
        this.logger.info({ tokenPrefix: accessToken.substring(0, 8) }, 'Token expired');
        this.tokens.delete(accessToken);
        return null;
      }

      return token;
    }
  }

  /**
   * Revoke a token
   */
  async revokeToken(accessToken: string): Promise<boolean> {
    if (this.redis) {
      const key = `harvest:token:${accessToken}`;
      const result = await this.redis.del(key);
      const existed = result > 0;
      if (existed) {
        this.logger.info({ tokenPrefix: accessToken.substring(0, 8) }, 'Token revoked');
      }
      return existed;
    } else {
      const existed = this.tokens.delete(accessToken);
      if (existed) {
        this.logger.info({ tokenPrefix: accessToken.substring(0, 8) }, 'Token revoked');
      }
      return existed;
    }
  }

  /**
   * Clean up expired tokens
   */
  private cleanupExpiredTokens(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [token, data] of this.tokens.entries()) {
      if (now > data.expiresAt) {
        this.tokens.delete(token);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.info({ count: cleaned }, 'Cleaned up expired tokens');
    }
  }

  /**
   * Get count of active tokens
   */
  getTokenCount(): number {
    return this.tokens.size;
  }

  /**
   * Store a new authorization code
   */
  async storeAuthCode(
    harvestTokens: HarvestTokens,
    harvestAccountId: string,
    harvestUserId: number,
    redirectUri: string
  ): Promise<string> {
    const code = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    const authCodeData: StoredAuthCode = {
      code,
      harvestTokens,
      harvestAccountId,
      harvestUserId,
      redirectUri,
      expiresAt,
      createdAt: Date.now(),
    };

    if (this.redis) {
      // Store in Redis with TTL
      const key = `harvest:authcode:${code}`;
      const ttlSeconds = Math.floor((expiresAt - Date.now()) / 1000);
      await this.redis.setex(key, ttlSeconds, JSON.stringify(authCodeData));
    } else {
      // Store in memory
      this.authCodes.set(code, authCodeData);
    }

    this.logger.info(
      { userId: harvestUserId, codePrefix: code.substring(0, 8) },
      'Stored new authorization code'
    );

    // Clean up expired auth codes (in-memory only)
    if (!this.redis) {
      this.cleanupExpiredAuthCodes();
    }

    return code;
  }

  /**
   * Retrieve and consume authorization code (one-time use)
   */
  async consumeAuthCode(code: string, redirectUri: string): Promise<StoredAuthCode | null> {
    if (this.redis) {
      // Get from Redis
      const key = `harvest:authcode:${code}`;
      const data = await this.redis.get(key);

      if (!data) {
        this.logger.warn({ codePrefix: code.substring(0, 8) }, 'Authorization code not found');
        return null;
      }

      let authCode: StoredAuthCode;
      try {
        authCode = JSON.parse(data) as StoredAuthCode;
      } catch (error) {
        this.logger.error({ error }, 'Failed to parse auth code from Redis');
        await this.redis.del(key);
        return null;
      }

      // Check if expired
      if (Date.now() > authCode.expiresAt) {
        this.logger.info({ codePrefix: code.substring(0, 8) }, 'Authorization code expired');
        await this.redis.del(key);
        return null;
      }

      // Verify redirect URI matches
      if (authCode.redirectUri !== redirectUri) {
        this.logger.warn(
          {
            codePrefix: code.substring(0, 8),
            expected: authCode.redirectUri,
            received: redirectUri,
          },
          'Redirect URI mismatch'
        );
        return null;
      }

      // Delete code after use (one-time use)
      await this.redis.del(key);
      this.logger.info({ codePrefix: code.substring(0, 8) }, 'Authorization code consumed');

      return authCode;
    } else {
      // Get from memory
      const authCode = this.authCodes.get(code);

      if (!authCode) {
        this.logger.warn({ codePrefix: code.substring(0, 8) }, 'Authorization code not found');
        return null;
      }

      // Check if expired
      if (Date.now() > authCode.expiresAt) {
        this.logger.info({ codePrefix: code.substring(0, 8) }, 'Authorization code expired');
        this.authCodes.delete(code);
        return null;
      }

      // Verify redirect URI matches
      if (authCode.redirectUri !== redirectUri) {
        this.logger.warn(
          {
            codePrefix: code.substring(0, 8),
            expected: authCode.redirectUri,
            received: redirectUri,
          },
          'Redirect URI mismatch'
        );
        return null;
      }

      // Delete code after use (one-time use)
      this.authCodes.delete(code);
      this.logger.info({ codePrefix: code.substring(0, 8) }, 'Authorization code consumed');

      return authCode;
    }
  }

  /**
   * Clean up expired authorization codes
   */
  private cleanupExpiredAuthCodes(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [code, data] of this.authCodes.entries()) {
      if (now > data.expiresAt) {
        this.authCodes.delete(code);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.info({ count: cleaned }, 'Cleaned up expired authorization codes');
    }
  }
}
