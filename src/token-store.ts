/**
 * Authorization code store for OAuth provider with Redis support
 * Handles temporary authorization codes (5 min TTL) for OAuth flow
 * Falls back to in-memory storage if Redis is not available
 *
 * Note: Access tokens are now handled by JWT service (stateless)
 */
import { randomBytes } from 'crypto';
import type { Redis } from 'ioredis';
import { HarvestTokens } from './harvest-client.js';
import { Logger } from './logger.js';

export interface StoredAuthCode {
  code: string;
  harvestTokens: HarvestTokens;
  harvestAccountId: string;
  harvestUserId: number;
  redirectUri: string;
  expiresAt: number;
  createdAt: number;
}

export class AuthCodeStore {
  private authCodes: Map<string, StoredAuthCode> = new Map();
  private logger: Logger;
  private redis: Redis | null;

  constructor(logger: Logger, redis: Redis | null = null) {
    this.logger = logger;
    this.redis = redis;

    if (redis) {
      this.logger.info('AuthCodeStore using Redis for persistence');
    } else {
      this.logger.info('AuthCodeStore using in-memory storage');
    }
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
   * Clean up expired authorization codes (in-memory only)
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

  /**
   * Get count of active authorization codes (for testing/monitoring)
   */
  getAuthCodeCount(): number {
    return this.authCodes.size;
  }
}
