/**
 * Session type definitions and middleware
 */
import { Request, Response, NextFunction } from 'express';
import { Session, SessionData } from 'express-session';
import { HarvestTokens } from './harvest-client.js';
import { Logger } from './logger.js';

// Extend express-session types
declare module 'express-session' {
  interface SessionData {
    harvestTokens?: HarvestTokens;
    harvestAccountId?: string;
    harvestUserId?: number;
    oauthState?: string;
    tokenExpiresAt?: number;
    // OAuth provider fields (for MCP clients)
    oauthClientId?: string;
    oauthRedirectUri?: string;
    oauthClientState?: string;
    authorizationCode?: {
      code: string;
      harvestTokens: HarvestTokens;
      harvestAccountId: string;
      harvestUserId: number;
      redirectUri: string;
      expiresAt: number;
    };
  }
}

/**
 * Middleware to check if user is authenticated
 */
export function requireAuth(logger: Logger) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.session.harvestTokens || !req.session.harvestAccountId) {
      logger.warn({ path: req.path }, 'Unauthorized access attempt');
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Please authenticate with Harvest first',
        authUrl: '/auth/harvest',
      });
    }

    // Check if token is expired (with 5 minute buffer)
    const now = Date.now();
    if (req.session.tokenExpiresAt && req.session.tokenExpiresAt < now + 5 * 60 * 1000) {
      logger.info('Access token expired or expiring soon');
      return res.status(401).json({
        error: 'Token expired',
        message: 'Your session has expired. Please re-authenticate.',
        authUrl: '/auth/harvest',
      });
    }

    next();
  };
}

/**
 * Get Harvest tokens from session
 */
export function getHarvestTokens(session: Session & Partial<SessionData>): { tokens: HarvestTokens; accountId: string } | null {
  if (!session.harvestTokens || !session.harvestAccountId) {
    return null;
  }

  return {
    tokens: session.harvestTokens,
    accountId: session.harvestAccountId,
  };
}
