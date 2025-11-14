/**
 * Redis client factory and utilities
 */
import { Redis } from 'ioredis';
import { Config } from './config.js';
import { Logger } from './logger.js';

/**
 * Creates a Redis client based on configuration
 * Returns null if Redis is not configured
 */
export function createRedisClient(config: Config, logger: Logger): Redis | null {
  // Check if Redis is configured
  if (!config.redisUrl && !config.redisHost) {
    logger.info('Redis not configured, using in-memory storage');
    return null;
  }

  try {
    let redis: Redis;

    if (config.redisUrl) {
      // Connect using URL
      logger.info({ redisUrl: config.redisUrl.replace(/:[^:@]+@/, ':****@') }, 'Connecting to Redis via URL');
      redis = new Redis(config.redisUrl, {
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        lazyConnect: false,
      });
    } else {
      // Connect using individual parameters
      const redisOptions: any = {
        host: config.redisHost!,
        port: config.redisPort || 6379,
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        lazyConnect: false,
      };

      if (config.redisPassword) {
        redisOptions.password = config.redisPassword;
      }

      if (config.redisTls) {
        redisOptions.tls = {};
      }

      logger.info({
        host: config.redisHost,
        port: config.redisPort || 6379,
        tls: config.redisTls,
      }, 'Connecting to Redis');

      redis = new Redis(redisOptions);
    }

    // Handle connection events
    redis.on('connect', () => {
      logger.info('Redis client connected');
    });

    redis.on('ready', () => {
      logger.info('Redis client ready');
    });

    redis.on('error', (error: Error) => {
      logger.error({ error }, 'Redis client error');
    });

    redis.on('close', () => {
      logger.warn('Redis connection closed');
    });

    redis.on('reconnecting', () => {
      logger.info('Redis client reconnecting');
    });

    return redis;
  } catch (error) {
    logger.error({ error }, 'Failed to create Redis client');
    throw error;
  }
}

/**
 * Gracefully closes a Redis client
 */
export async function closeRedisClient(redis: Redis | null, logger: Logger): Promise<void> {
  if (!redis) {
    return;
  }

  try {
    logger.info('Closing Redis connection');
    await redis.quit();
    logger.info('Redis connection closed');
  } catch (error) {
    logger.error({ error }, 'Error closing Redis connection');
    // Force disconnect if quit fails
    redis.disconnect();
  }
}
