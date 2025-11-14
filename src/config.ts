/**
 * Configuration module for environment variables
 */

export interface Config {
  // OAuth Configuration (for Harvest)
  harvestOAuthClientId: string;
  harvestOAuthClientSecret: string;
  oauthRedirectUri: string;

  // OAuth Provider Configuration (for MCP clients)
  serverBaseUrl: string;

  // Session Configuration
  sessionSecret: string;

  // Server Configuration
  port: number;
  nodeEnv: string;

  // Harvest Configuration
  standardWorkDayHours: number;
  timezone: string;

  // Logging Configuration
  logLevel: string;

  // Redis Configuration (optional - falls back to in-memory if not set)
  redisUrl?: string;
  redisHost?: string;
  redisPort?: number;
  redisPassword?: string;
  redisTls?: boolean;
}

function getRequiredEnvVar(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Required environment variable ${name} is not set`);
  }
  return value;
}

function getOptionalEnvVar(name: string, defaultValue: string): string {
  return process.env[name] || defaultValue;
}

export function loadConfig(): Config {
  const port = parseInt(getOptionalEnvVar('PORT', '3000'), 10);
  const serverBaseUrl = getOptionalEnvVar('SERVER_BASE_URL', `http://localhost:${port}`);

  // Parse Redis configuration
  const redisUrl = process.env.REDIS_URL;
  const redisHost = process.env.REDIS_HOST;
  const redisPort = process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT, 10) : undefined;
  const redisPassword = process.env.REDIS_PASSWORD;
  const redisTls = process.env.REDIS_TLS === 'true';

  return {
    // OAuth Configuration (for Harvest)
    harvestOAuthClientId: getRequiredEnvVar('HARVEST_OAUTH_CLIENT_ID'),
    harvestOAuthClientSecret: getRequiredEnvVar('HARVEST_OAUTH_CLIENT_SECRET'),
    oauthRedirectUri: getRequiredEnvVar('OAUTH_REDIRECT_URI'),

    // OAuth Provider Configuration (for MCP clients)
    serverBaseUrl,

    // Session Configuration
    sessionSecret: getRequiredEnvVar('SESSION_SECRET'),

    // Server Configuration
    port,
    nodeEnv: getOptionalEnvVar('NODE_ENV', 'development'),

    // Harvest Configuration
    standardWorkDayHours: parseFloat(getOptionalEnvVar('STANDARD_WORK_DAY_HOURS', '7.5')),
    timezone: getOptionalEnvVar('TIMEZONE', 'Australia/Perth'),

    // Logging Configuration
    logLevel: getOptionalEnvVar('LOG_LEVEL', 'info'),

    // Redis Configuration (optional)
    redisUrl,
    redisHost,
    redisPort,
    redisPassword,
    redisTls,
  };
}
