/**
 * In-memory token store for OAuth provider
 * Maps local access tokens to Harvest credentials
 */
import { randomBytes } from 'crypto';
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

  constructor(logger: Logger) {
    this.logger = logger;
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
  storeToken(
    harvestTokens: HarvestTokens,
    harvestAccountId: string,
    harvestUserId: number
  ): string {
    const accessToken = this.generateToken();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days

    this.tokens.set(accessToken, {
      accessToken,
      harvestTokens,
      harvestAccountId,
      harvestUserId,
      expiresAt,
      createdAt: Date.now(),
    });

    this.logger.info(
      { userId: harvestUserId, tokenPrefix: accessToken.substring(0, 8) },
      'Stored new access token'
    );

    // Clean up expired tokens
    this.cleanupExpiredTokens();

    return accessToken;
  }

  /**
   * Retrieve token data by access token
   */
  getToken(accessToken: string): StoredToken | null {
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

  /**
   * Revoke a token
   */
  revokeToken(accessToken: string): boolean {
    const existed = this.tokens.delete(accessToken);
    if (existed) {
      this.logger.info({ tokenPrefix: accessToken.substring(0, 8) }, 'Token revoked');
    }
    return existed;
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
  storeAuthCode(
    harvestTokens: HarvestTokens,
    harvestAccountId: string,
    harvestUserId: number,
    redirectUri: string
  ): string {
    const code = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    this.authCodes.set(code, {
      code,
      harvestTokens,
      harvestAccountId,
      harvestUserId,
      redirectUri,
      expiresAt,
      createdAt: Date.now(),
    });

    this.logger.info(
      { userId: harvestUserId, codePrefix: code.substring(0, 8) },
      'Stored new authorization code'
    );

    // Clean up expired auth codes
    this.cleanupExpiredAuthCodes();

    return code;
  }

  /**
   * Retrieve and consume authorization code (one-time use)
   */
  consumeAuthCode(code: string, redirectUri: string): StoredAuthCode | null {
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
