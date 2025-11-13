/**
 * Tests for session middleware
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { Session } from 'express-session';
import { requireAuth, getHarvestTokens } from '../session.js';
import { HarvestTokens } from '../harvest-client.js';
import pino from 'pino';

describe('Session Middleware', () => {
  let mockLogger: pino.Logger;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let jsonSpy: jest.Mock;
  let statusSpy: jest.Mock;

  beforeEach(() => {
    mockLogger = pino({ level: 'silent' });
    jsonSpy = jest.fn() as any;
    statusSpy = jest.fn(() => ({ json: jsonSpy })) as any;

    mockReq = {
      session: {} as Session,
      path: '/test',
    };

    mockRes = {
      status: statusSpy,
      json: jsonSpy,
    } as any;

    mockNext = jest.fn() as NextFunction;
  });

  describe('requireAuth', () => {
    it('should allow authenticated requests', () => {
      const tokens: HarvestTokens = {
        access_token: 'test-token',
        refresh_token: 'test-refresh',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockReq.session = {
        harvestTokens: tokens,
        harvestAccountId: '12345',
        tokenExpiresAt: Date.now() + 3600 * 1000,
      } as any;

      const middleware = requireAuth(mockLogger);
      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(statusSpy).not.toHaveBeenCalled();
    });

    it('should reject unauthenticated requests', () => {
      mockReq.session = {} as Session;

      const middleware = requireAuth(mockLogger);
      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(statusSpy).toHaveBeenCalledWith(401);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Unauthorized',
          authUrl: '/auth/harvest',
        })
      );
    });

    it('should reject requests with expired tokens', () => {
      const tokens: HarvestTokens = {
        access_token: 'test-token',
        refresh_token: 'test-refresh',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockReq.session = {
        harvestTokens: tokens,
        harvestAccountId: '12345',
        tokenExpiresAt: Date.now() - 1000, // Expired 1 second ago
      } as any;

      const middleware = requireAuth(mockLogger);
      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(statusSpy).toHaveBeenCalledWith(401);
      expect(jsonSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Token expired',
        })
      );
    });

    it('should reject requests with missing account ID', () => {
      const tokens: HarvestTokens = {
        access_token: 'test-token',
        refresh_token: 'test-refresh',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockReq.session = {
        harvestTokens: tokens,
        // Missing harvestAccountId
      } as any;

      const middleware = requireAuth(mockLogger);
      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(statusSpy).toHaveBeenCalledWith(401);
    });
  });

  describe('getHarvestTokens', () => {
    it('should return tokens and account ID when present', () => {
      const tokens: HarvestTokens = {
        access_token: 'test-token',
        refresh_token: 'test-refresh',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      const session = {
        harvestTokens: tokens,
        harvestAccountId: '12345',
      } as any;

      const result = getHarvestTokens(session);

      expect(result).not.toBeNull();
      expect(result?.tokens).toEqual(tokens);
      expect(result?.accountId).toBe('12345');
    });

    it('should return null when tokens are missing', () => {
      const session = {
        harvestAccountId: '12345',
      } as any;

      const result = getHarvestTokens(session);

      expect(result).toBeNull();
    });

    it('should return null when account ID is missing', () => {
      const tokens: HarvestTokens = {
        access_token: 'test-token',
        refresh_token: 'test-refresh',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      const session = {
        harvestTokens: tokens,
      } as any;

      const result = getHarvestTokens(session);

      expect(result).toBeNull();
    });

    it('should return null when both are missing', () => {
      const session = {} as any;

      const result = getHarvestTokens(session);

      expect(result).toBeNull();
    });
  });
});
