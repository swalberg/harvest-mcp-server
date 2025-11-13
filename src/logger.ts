/**
 * Structured logging with Pino
 */
import pino from 'pino';
import { createRequire } from 'module';
import { Config } from './config.js';

const require = createRequire(import.meta.url);

/**
 * Check if pino-pretty is available (only in devDependencies)
 */
function isPinoPrettyAvailable(): boolean {
  try {
    // Try to resolve pino-pretty synchronously
    require.resolve('pino-pretty');
    return true;
  } catch {
    return false;
  }
}

export function createLogger(config: Config) {
  // Use pretty printing only in development AND if pino-pretty is available
  const usePretty = config.nodeEnv === 'development' && isPinoPrettyAvailable();

  return pino({
    level: config.logLevel,
    // Format logs as JSON for container environments
    ...(usePretty
      ? {
          // Development: Pretty print (if available)
          transport: {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'HH:MM:ss Z',
              ignore: 'pid,hostname',
            },
          },
        }
      : {
          // Production or no pino-pretty: JSON only
        }),
    // Redact sensitive fields
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'res.headers["set-cookie"]',
        'access_token',
        'refresh_token',
        'sessionSecret',
      ],
      censor: '[REDACTED]',
    },
  });
}

export type Logger = ReturnType<typeof createLogger>;
