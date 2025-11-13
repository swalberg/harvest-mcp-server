#!/usr/bin/env node
/**
 * Main HTTP server entry point
 */
import { loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { createApp } from './app.js';

// Load configuration
const config = loadConfig();
const logger = createLogger(config);

// Create app
const app = createApp(config, logger);

// Start server
const server = app.listen(config.port, () => {
  logger.info(
    {
      port: config.port,
      nodeEnv: config.nodeEnv,
    },
    'Harvest MCP Server started'
  );
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception');
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.fatal({ reason }, 'Unhandled rejection');
  process.exit(1);
});
