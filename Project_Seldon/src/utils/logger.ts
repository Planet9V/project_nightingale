// File: src/utils/logger.ts
import winston from 'winston';
import { ElasticsearchTransport } from 'winston-elasticsearch';

const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: {
    service: 'etl-pipeline',
    version: process.env.npm_package_version
  },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
      level: process.env.LOG_LEVEL || 'info'
    }),
    
    // File transport
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 5
    }),
    
    // Elasticsearch transport for production
    ...(process.env.NODE_ENV === 'production' ? [
      new ElasticsearchTransport({
        level: 'info',
        clientOpts: {
          node: process.env.ELASTICSEARCH_URL
        },
        index: 'etl-logs'
      })
    ] : [])
  ]
});

// Structured logging helpers
export function logOperation(operation: string, metadata: any) {
  logger.info(`Operation: ${operation}`, {
    operation,
    timestamp: new Date().toISOString(),
    ...metadata
  });
}

// Export the logger instance
export { logger };

// PROGRESS: [1.3.2] Logging infrastructure - COMPLETED