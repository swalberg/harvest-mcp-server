/**
 * JWT service for issuing and verifying access tokens
 * Uses JWT with encrypted Harvest credentials for stateless authentication
 */
import jwt from 'jsonwebtoken';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import { HarvestTokens } from './harvest-client.js';
import { Logger } from './logger.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;

export interface JwtPayload {
  sub: string; // User ID
  accountId: string; // Harvest account ID
  userId: number; // Harvest user ID
  encryptedTokens: string; // Encrypted Harvest tokens
  iat?: number; // Issued at
  exp?: number; // Expiration
}

export interface DecodedToken {
  userId: number;
  accountId: string;
  harvestTokens: HarvestTokens;
}

export class JwtService {
  private jwtSecret: string;
  private encryptionKey: Buffer;
  private logger: Logger;
  private expirationSeconds: number;

  constructor(secret: string, logger: Logger, expirationDays: number = 7) {
    this.jwtSecret = secret;
    this.logger = logger;
    this.expirationSeconds = expirationDays * 24 * 60 * 60;

    // Derive 256-bit encryption key from secret using SHA-256
    this.encryptionKey = createHash('sha256').update(secret).digest();
  }

  /**
   * Encrypt Harvest tokens using AES-256-GCM
   */
  private encryptTokens(tokens: HarvestTokens): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv);

    const data = JSON.stringify(tokens);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Combine IV + authTag + encrypted data
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return combined.toString('base64');
  }

  /**
   * Decrypt Harvest tokens using AES-256-GCM
   */
  private decryptTokens(encryptedData: string): HarvestTokens {
    const combined = Buffer.from(encryptedData, 'base64');

    // Extract IV, authTag, and encrypted data
    const iv = combined.subarray(0, IV_LENGTH);
    const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const encrypted = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = createDecipheriv(ALGORITHM, this.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8')) as HarvestTokens;
  }

  /**
   * Generate a JWT access token with encrypted Harvest credentials
   */
  generateToken(
    harvestTokens: HarvestTokens,
    accountId: string,
    userId: number
  ): string {
    const encryptedTokens = this.encryptTokens(harvestTokens);

    const payload: Omit<JwtPayload, 'iat' | 'exp'> = {
      sub: userId.toString(),
      accountId,
      userId,
      encryptedTokens,
    };

    const token = jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.expirationSeconds,
    });

    this.logger.info(
      { userId, accountId, expiresIn: `${this.expirationSeconds}s` },
      'Generated JWT access token'
    );

    return token;
  }

  /**
   * Verify and decode a JWT token
   * Returns null if token is invalid or expired
   */
  verifyToken(token: string): DecodedToken | null {
    try {
      const payload = jwt.verify(token, this.jwtSecret) as JwtPayload;

      const harvestTokens = this.decryptTokens(payload.encryptedTokens);

      return {
        userId: payload.userId,
        accountId: payload.accountId,
        harvestTokens,
      };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        this.logger.info('JWT token expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        this.logger.warn({ error: error.message }, 'Invalid JWT token');
      } else {
        this.logger.error({ error }, 'Failed to verify JWT token');
      }
      return null;
    }
  }

  /**
   * Decode token without verification (for debugging/logging only)
   */
  decodeToken(token: string): JwtPayload | null {
    try {
      return jwt.decode(token) as JwtPayload;
    } catch (error) {
      this.logger.error({ error }, 'Failed to decode JWT token');
      return null;
    }
  }

  /**
   * Get remaining TTL for a token in seconds
   */
  getTokenTtl(token: string): number | null {
    const decoded = this.decodeToken(token);
    if (!decoded || !decoded.exp) {
      return null;
    }

    const now = Math.floor(Date.now() / 1000);
    const ttl = decoded.exp - now;
    return ttl > 0 ? ttl : 0;
  }
}
