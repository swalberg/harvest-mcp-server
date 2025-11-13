/**
 * OAuth 2.0 authentication for Harvest
 */
import axios from 'axios';
import { Config } from './config.js';
import { Logger } from './logger.js';
import { HarvestTokens } from './harvest-client.js';

export class OAuthService {
  private config: Config;
  private logger: Logger;

  constructor(config: Config, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }

  /**
   * Get the authorization URL to redirect users to Harvest
   */
  getAuthorizationUrl(state: string): string {
    const params = new URLSearchParams({
      client_id: this.config.harvestOAuthClientId,
      redirect_uri: this.config.oauthRedirectUri,
      state,
      response_type: 'code',
    });

    return `https://id.getharvest.com/oauth2/authorize?${params.toString()}`;
  }

  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForToken(code: string): Promise<HarvestTokens & { account_id: string }> {
    try {
      this.logger.info('Exchanging authorization code for access token');

      const params = new URLSearchParams({
        code,
        client_id: this.config.harvestOAuthClientId,
        client_secret: this.config.harvestOAuthClientSecret,
        redirect_uri: this.config.oauthRedirectUri,
        grant_type: 'authorization_code',
      });

      const response = await axios.post(
        'https://id.getharvest.com/api/v2/oauth2/token',
        params.toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );

      this.logger.info('Successfully obtained access token');

      // Harvest returns account information in the token response
      const { access_token, refresh_token, expires_in, token_type } = response.data;

      // Get account ID from the token info
      const accountId = await this.getAccountIdFromToken(access_token);

      return {
        access_token,
        refresh_token,
        expires_in,
        token_type,
        account_id: accountId,
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        this.logger.error(
          {
            status: error.response?.status,
            data: error.response?.data,
          },
          'Failed to exchange code for token'
        );
        throw new Error(`OAuth token exchange failed: ${error.response?.data?.error_description || error.message}`);
      }
      throw error;
    }
  }

  /**
   * Refresh an expired access token
   */
  async refreshAccessToken(refreshToken: string): Promise<HarvestTokens & { account_id: string }> {
    try {
      this.logger.info('Refreshing access token');

      const params = new URLSearchParams({
        refresh_token: refreshToken,
        client_id: this.config.harvestOAuthClientId,
        client_secret: this.config.harvestOAuthClientSecret,
        grant_type: 'refresh_token',
      });

      const response = await axios.post(
        'https://id.getharvest.com/api/v2/oauth2/token',
        params.toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );

      this.logger.info('Successfully refreshed access token');

      const { access_token, refresh_token, expires_in, token_type } = response.data;

      // Get account ID from the refreshed token
      const accountId = await this.getAccountIdFromToken(access_token);

      return {
        access_token,
        refresh_token: refresh_token || refreshToken, // Use new refresh token if provided, else keep old one
        expires_in,
        token_type,
        account_id: accountId,
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        this.logger.error(
          {
            status: error.response?.status,
            data: error.response?.data,
          },
          'Failed to refresh access token'
        );
        throw new Error(`Token refresh failed: ${error.response?.data?.error_description || error.message}`);
      }
      throw error;
    }
  }

  /**
   * Get account ID from access token by calling Harvest API
   */
  private async getAccountIdFromToken(accessToken: string): Promise<string> {
    try {
      // Get user's accounts
      const response = await axios.get('https://id.getharvest.com/api/v2/accounts', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'User-Agent': 'Harvest MCP Server (oauth@example.com)',
        },
      });

      const accounts = response.data.accounts;
      if (!accounts || accounts.length === 0) {
        throw new Error('No Harvest accounts found for this user');
      }

      // Use the first account (single-tenant application)
      const accountId = accounts[0].id.toString();
      this.logger.info({ accountId }, 'Retrieved account ID from token');

      return accountId;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        this.logger.error(
          {
            status: error.response?.status,
            data: error.response?.data,
          },
          'Failed to get account ID from token'
        );
        throw new Error(`Failed to get account information: ${error.message}`);
      }
      throw error;
    }
  }
}
