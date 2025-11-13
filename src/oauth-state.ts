/**
 * Stateless OAuth state management using cryptographic signing
 * This eliminates the need for session persistence for OAuth state
 */
import { createHmac, randomBytes } from 'crypto';

export interface OAuthStateData {
  nonce: string;
  timestamp: number;
  clientId?: string;
  redirectUri?: string;
  clientState?: string;
}

export class OAuthStateManager {
  private readonly secret: string;
  private readonly ttl: number = 10 * 60 * 1000; // 10 minutes

  constructor(secret: string) {
    this.secret = secret;
  }

  /**
   * Create a signed OAuth state token
   */
  createState(data: Partial<OAuthStateData> = {}): string {
    const stateData: OAuthStateData = {
      nonce: randomBytes(16).toString('hex'),
      timestamp: Date.now(),
      ...data,
    };

    const payload = Buffer.from(JSON.stringify(stateData)).toString('base64url');
    const signature = this.sign(payload);

    return `${payload}.${signature}`;
  }

  /**
   * Verify and decode a signed OAuth state token
   */
  verifyState(state: string): OAuthStateData | null {
    try {
      const parts = state.split('.');
      if (parts.length !== 2) {
        return null;
      }

      const [payload, signature] = parts;

      // Verify signature
      const expectedSignature = this.sign(payload);
      if (signature !== expectedSignature) {
        return null;
      }

      // Decode payload
      const stateData: OAuthStateData = JSON.parse(
        Buffer.from(payload, 'base64url').toString('utf8')
      );

      // Check timestamp
      if (Date.now() - stateData.timestamp > this.ttl) {
        return null;
      }

      return stateData;
    } catch {
      return null;
    }
  }

  private sign(payload: string): string {
    return createHmac('sha256', this.secret)
      .update(payload)
      .digest('base64url');
  }
}
